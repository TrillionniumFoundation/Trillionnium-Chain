#!/usr/bin/env python3
"""Package this fixed recovered campaign after completion; never launch tests/Cargo."""
from __future__ import annotations

import ast
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

BASE = Path('/home/qq/trnm-v4-e12ecc-recovery')
ROOT = BASE / 'repo'
SOURCE = '0d99924005b70b1308bf3e62c53e9300fbb4aac4'
INITIAL = 'db48af79b9686f2c7bb50ff7dde9b2233fe32fb8'
TREES = {SOURCE: '9358521d635df532d71b807fab8cc3029ff83912',
         INITIAL: '283c2c6c6c222eaf71e6935c39cceccb3e9e2df2'}
RUN = BASE / 'exact-0d999240'
INITIAL_ROOT = BASE / 'initial-evidence'
OLD_RUN = INITIAL_ROOT / 'exact-db48af79'
OUT = BASE / 'staged-evidence/pq-root-continuation-v4-20261109'
CLI_SHA256 = 'd4c13f27791f214bc9ea80acb1ed51fa1fbc7c17db72b9a7c54e24bf0accc171'
PREPARATION_SHA256 = 'ccdcf7e8bb9871607c73adc78624a607b616c227b7fe581b96c48761a3805bfa'
OPENSSL_ARCHIVE_SHA256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
CORRECTED_JOB_SHA256 = 'd0a1f0d78b2cfec5d12209ab2c252411876c25279becf654e5e09bc9d8758228'
DOMAINS = ('application', 'commitment', 'ledger', 'proof', 'recovery', 'release', 'signature', 'transport')
FALSE_QUALIFICATION = (
    'whole_chain_pq_qualified', 'composition_coverage_proved',
    'whole_chain_hash_query_scope_closed', 'independent_custody_verified',
    'anchor_independence_verified', 'freshness_source_authenticated',
    'evidence_authenticity_verified', 'enrolled_key_binding_verified',
    'independent_common_restore_exclusion_proved', 'recovery_floor_installation_authorized',
    'actual_external_effects_verified', 'native_m15_production_integration_complete',
    'migration_authorized', 'transitive_dependency_closure_proved', 'production_activation',
    'continuous_source_immutability_proved', 'independent_execution_provenance_authenticated',
    'full_protocol_lane_executed', 'full_workspace_tests_executed',
)
READERS = (
    ('custody-controls', 'test_pq_root_custody_review_v1.py'),
    ('custody-review', 'pq_root_custody_review_v1.py'),
    ('migration-controls', 'test_pq_root_migration_review_v1.py'),
    ('migration-review', 'pq_root_migration_review_v1.py'),
    ('continuation-runner-controls', 'test_run_pq_root_continuation_v4.py'),
    ('feature-and-registry-controls', 'test_authenticated_suite_count.py'),
    ('dependency-controls', 'test_pq_root_dependency_register.py'),
    ('dependency-register', 'pq_root_dependency_register.py'),
    ('native-runner-controls', 'test_run_pq_root_native_v3.py'),
    ('ci-contract-controls', 'test_ci_contract.py'), ('ci-contract', 'check_ci_contract.py'),
    ('source-integrity-controls', 'test_ci_source_integrity.py'),
    ('pq-source-controls', 'test_pq_research_integration.py'),
    ('pq-source-corpus', 'check_pq_research_integration.py'),
    ('lifetime-controls', 'test_pq_lifetime_budget.py'), ('lifetime-register', 'pq_lifetime_budget.py'),
    ('claim-controls', 'test_pq_chain_claim_guard.py'), ('claim-guard', 'pq_chain_claim_guard.py'),
    ('authority-controls', 'test_pq_authority_effect_register.py'),
    ('authority-register', 'pq_authority_effect_register.py'), ('repository-links', 'check_repository.py'),
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def raw(path):
    need(path.is_file() and not path.is_symlink(), 'missing regular file: ' + str(path))
    return path.read_bytes()


def read(path):
    return json.loads(raw(path))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def frozen(path, source=SOURCE):
    # Git object reads only; never execute checkout Python or Cargo.
    return subprocess.check_output(['git', 'show', source + ':' + path], cwd=ROOT)


def held(value):
    need(value.get('status') == 'HOLD', 'qualification status must remain HOLD')
    need('actual_lifetime_failure_bound' in value and value['actual_lifetime_failure_bound'] is None,
         'actual risk bound must remain null')
    for key in FALSE_QUALIFICATION:
        if key in value:
            need(value[key] is False, 'qualification promotion refused: ' + key)


def source_check(value, source):
    need(value.get('schema') == 'trnm-ci-source-v1' and value.get('kind') == 'head', 'head source receipt required')
    need(value.get('tested_commit') == source and value.get('candidate') == source, 'wrong observed source')
    need(value.get('tested_tree') == TREES[source], 'wrong observed source tree')
    need(value.get('tracked_worktree_verified') is True, 'tracked source check missing')
    need(value.get('tests_executed_by_identity_check') is False, 'identity check cannot claim execution')
    for key in ('tracked_entries', 'tracked_bytes'):
        need(type(value.get(key)) is int and value[key] > 0, 'invalid ' + key)


def source_pair(folder, source):
    before, after = read(folder / 'source-before.json'), read(folder / 'source-after.json')
    source_check(before, source)
    source_check(after, source)
    need(before == after, 'source endpoints differ: ' + str(folder))
    return before


def plan(output, openssl, corrected=True):
    commands = [('preflight', ['bash', 'scripts/project-preflight.sh', '--audit']),
                ('versions-rust', ['rustc', '--version', '--verbose']),
                ('versions-openssl', [openssl, 'version', '-a'])]
    commands += [(name, ['python3', 'scripts/ci/' + script]) for name, script in READERS
                 if corrected or name != 'feature-and-registry-controls']
    commands += [('inventory', ['python3', 'scripts/refresh_distributed_source_inventory.py', '--check']),
                 ('implementation-summary', ['python3', 'scripts/ci/report_current_implementation.py', '--check']),
                 ('format', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'])]
    for name, manifest, flags in [('graph-default', 'trillionnium/Cargo.toml', []),
                                  ('graph-all-features', 'trillionnium/Cargo.toml', ['--all-features']),
                                  ('graph-fuzz', 'tests/fuzz/Cargo.toml', [])]:
        commands.append((name, ['cargo', 'metadata', '--locked', '--manifest-path', manifest, '--format-version', '1'] + flags))
    clippy = ('workspace-clippy', ['cargo', 'clippy', '--locked', '--manifest-path', 'trillionnium/Cargo.toml',
                                  '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'])
    if corrected:
        commands.append(clippy)
    commands += [('v4-native', ['python3', 'scripts/ci/run_pq_root_continuation_v4.py', '--out', str(output / 'native-v4')]),
                 ('v3-native', ['python3', 'scripts/ci/run_pq_root_native_v3.py', '--out', str(output / 'native-v3')])]
    for name, filename in [('v2-policy', 'test_pq_root_recovery_policy_v1.py'),
                           ('v2-signature-structure', 'test_pq_root_recovery_signatures_v2.py'),
                           ('v2-provider-structure', 'test_pq_root_effect_readback_v2.py'),
                           ('v2-signature-native', 'test_pq_root_recovery_signatures_native_v2.py'),
                           ('v2-provider-native', 'test_pq_root_effect_readback_native_v2.py'),
                           ('v2-journal-native', 'test_pq_root_recovery_journal_native_v2.py')]:
        commands.append((name, ['python3', 'formal/pon-nakamoto-v1/' + filename, '-v']))
    for name, crate in [('retained-crypto-default', 'trnm-crypto-primitives'), ('retained-release-default', 'trnm-release-bundle')]:
        commands.append((name, ['cargo', 'test', '--locked', '--manifest-path', 'trillionnium/Cargo.toml', '-p', crate,
                                '--lib', '--', '--test-threads=1']))
    if not corrected:
        commands.append(clippy)
    commands.append(('diff-check', ['git', 'diff', '--check']))
    need(len(commands) == (42 if corrected else 41), 'fixed campaign plan changed')
    return commands


def records(folder, source, expected):
    rows = read(folder / 'commands.json')
    need(isinstance(rows, list) and len(rows) == len(expected), 'incomplete command roster: ' + str(folder))
    need([row.get('name') for row in rows] == [name for name, _ in expected], 'wrong command order/identity')
    need(len({row['name'] for row in rows}) == len(rows), 'duplicate command')
    for row, (name, argv) in zip(rows, expected):
        need(row.get('argv') == argv and row.get('source') == source, 'wrong source/argv: ' + name)
        need(type(row.get('exit_code')) is int and row['exit_code'] == 0, 'nonzero or absent completion: ' + name)
        need(row.get('log') == name + '.log', 'unexpected command log path')
        data = raw(folder / row['log'])
        need(row.get('bytes') == len(data) and row.get('sha256') == digest(data), 'log bytes/hash differ: ' + name)
    return rows


def native_plan(version, source):
    filename = 'scripts/ci/run_pq_root_' + ('continuation_v4.py' if version == 'v4' else 'native_v3.py')
    tree = ast.parse(frozen(filename, source).decode())
    constants = {node.targets[0].id: ast.literal_eval(node.value)
                 for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                 and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Tuple)}
    base = ['cargo', 'test', '--locked', '--manifest-path', 'trillionnium/Cargo.toml']
    suffix = ['--', '--nocapture', '--test-threads=1']
    if version == 'v4':
        base += ['-p', 'trnm-pon-node', '--features', 'pq-root-v3']
        result = [(label, base + ['--test', target] + suffix, constants[key]) for label, target, key in (
            ('recovery-floor', 'recovery_floor_v4_native', 'FLOOR'),
            ('provider-readback', 'root_effect_readback_v4_native', 'PROVIDER'),
            ('callback-budget', 'root_budget_v4_native', 'CALLBACK_BUDGET'))]
        counts = [8, 12, 6]
    else:
        result = [
            ('crypto-structure', base + ['-p', 'trnm-crypto-primitives', '--lib', 'pq_root_v3::tests::'] + suffix,
             tuple('pq_root_v3::tests::' + name for name in constants['CRYPTO_STRUCTURE'])),
            ('crypto-native', base + ['-p', 'trnm-crypto-primitives', '--features', 'pq-native-openssl', '--test', 'pq_root_v3_native'] + suffix,
             constants['CRYPTO_NATIVE']),
            ('root-kernel', base + ['-p', 'trnm-release-bundle', '--features', 'pq-root-v3', '--lib', 'root_recovery_v3::tests::'] + suffix,
             tuple('root_recovery_v3::tests::' + name for name in constants['KERNEL'])),
            ('root-owner', base + ['-p', 'trnm-pon-node', '--features', 'pq-root-v3', '--test', 'root_recovery_v3_native'] + suffix,
             constants['OWNER'])]
        counts = [10, 8, 12, 20]
    need([len(names) for _, _, names in result] == counts, 'reviewed native roster count changed')
    return result


def rust_observation(text, expected=None):
    summaries = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in .+$', text, re.M)
    need(len(summaries) == 1, 'one actual Rust summary required')
    status, passed, failed, ignored, measured, filtered = summaries[0]
    need(status == 'ok' and (int(failed), int(ignored), int(measured)) == (0, 0, 0), 'nonpassing Rust summary')
    observed = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (.+)$', text, re.M)
    names = [name for name, _ in observed]
    need(len(names) == int(passed) > 0 and len(names) == len(set(names)), 'missing/duplicate Rust tests')
    need(all(outcome == 'ok' for _, outcome in observed), 'unfinished Rust test')
    need(re.findall(r'^running (\d+) tests?$', text, re.M) == [passed], 'wrong Rust discovery')
    if expected is not None:
        need(set(names) == set(expected) and len(names) == len(expected), 'wrong exact native selectors')
    return {'tests': sorted(names), 'passed': int(passed), 'filtered_out': int(filtered)}


def native(folder, version, source):
    roster = native_plan(version, source)
    rows = records(folder, source, [(name, argv) for name, argv, _ in roster])
    summary = read(folder / 'summary.json')
    expected_schema = 'trnm-pq-root-continuation-native-v4' if version == 'v4' else 'trnm-pq-root-native-components-v3'
    need(summary.get('schema') == expected_schema and summary.get('source') == source, 'wrong native summary')
    held(summary)
    need(summary.get('commands') == rows and summary.get('component_execution_passed') is True, 'native summary mismatch')
    identity = source_pair(folder, source)
    for row, (_, _, names) in zip(rows, roster):
        observed = rust_observation(raw(folder / row['log']).decode(), names)
        need(row.get('error') is None and row.get('observation') == observed, 'native parsed observation mismatch')
    return {'component_execution_passed': True, 'commands_recorded': len(rows),
            'passed_tests': sum(row['observation']['passed'] for row in rows),
            'source_before_after_equal': True, 'source': identity,
            'command_log_hashes_verified': True,
            'observations': {row['name']: row['observation'] for row in rows},
            'scope': 'this component invocation only; same-process research fixtures'}


def python_counts(folder, rows):
    result = {}
    for row in rows:
        argv = row['argv']
        if argv[0] != 'python3' or not Path(argv[1]).name.startswith('test_'):
            continue
        text = raw(folder / row['log']).decode()
        matches = re.findall(r'^Ran (\d+) tests? in .+$', text, re.M)
        need(len(matches) == 1 and int(matches[0]) > 0, 'one nonempty Python suite required: ' + row['name'])
        need(re.findall(r'^OK(?:\s*\(.*\))?$', text, re.M) == ['OK'], 'Python failure/skips refused: ' + row['name'])
        result[row['name']] = int(matches[0])
    return result


def provider_check(environment):
    values = {}
    for line in raw(BASE / 'provider.env').decode().splitlines():
        key, value = line.split('=', 1)
        need(key not in values, 'duplicate provider environment key')
        values[key] = value
    need(set(values) == {'OPENSSL_DIR', 'OPENSSL_STATIC', 'TRNM_PQ_OPENSSL', 'TRNM_PQ_OPENSSL_SHA256',
                         'TRNM_PQ_OPENSSL_VERSION', 'OPENSSL_CONF', 'OPENSSL_MODULES'}, 'unexpected provider environment')
    need(all(environment.get(key) == value for key, value in values.items()), 'recorded provider environment differs')
    need(values['TRNM_PQ_OPENSSL_VERSION'] == '3.5.9' and values['OPENSSL_STATIC'] == '1', 'wrong recovered provider')
    need(values['TRNM_PQ_OPENSSL_SHA256'] == CLI_SHA256, 'unexpected recovered provider CLI')
    need(digest(raw(Path(values['TRNM_PQ_OPENSSL']))) == CLI_SHA256, 'provider CLI bytes changed')
    path = BASE / 'preparation/pq-provider/provider.json'
    receipt = read(path)
    need(receipt.get('schema') == 'trnm-ci-pq-provider-v3' and receipt.get('cli_executable') == values['TRNM_PQ_OPENSSL'],
         'wrong actual provider preparation receipt')
    need(receipt.get('version') == '3.5.9' and receipt.get('cli_sha256') == CLI_SHA256, 'provider receipt version/hash differ')
    need(receipt.get('preparation_script_sha256') == PREPARATION_SHA256, 'wrong preparation script receipt')
    need(receipt.get('source_archive_sha256_expected') == OPENSSL_ARCHIVE_SHA256, 'wrong OpenSSL archive receipt')
    need(receipt.get('exit_code') == 0 and receipt.get('result') == 'PREPARED_AND_SMOKE_VERIFIED'
         and receipt.get('source_digest_verified') is True and receipt.get('static_build') is True, 'incomplete provider preparation')
    for field in ('upstream_full_tests_run', 'independent_cryptographic_implementation_claim',
                  'native_rust_pq_tests_run_by_preparation', 'production_activation', 'whole_chain_quantum_security_qualified'):
        need(receipt.get(field) is False, 'provider preparation scope must remain limited: ' + field)
    prefix = Path(receipt['install_prefix'])
    need(str(prefix) == values['OPENSSL_DIR'], 'native include/library prefix differs')
    inputs = receipt.get('native_backend_inputs', [])
    need(len(inputs) == 5, 'five native provider inputs required')
    relative = []
    for item in inputs:
        item_path = Path(item['path'])
        relative.append(item_path.relative_to(prefix).as_posix())
        data = raw(item_path)
        need(len(data) == item['bytes'] and digest(data) == item['sha256'], 'provider native input changed')
    need(set(relative) == {'bin/openssl', 'include/openssl/opensslv.h', 'include/openssl/configuration.h',
                           'lib/libcrypto.a', 'lib/libssl.a'}, 'unexpected provider input inventory')
    return {'receipt': receipt, 'receipt_path': str(path.relative_to(BASE)),
            'receipt_sha256': digest(raw(path)), 'five_native_input_hashes_checked_at_packaging': True,
            'scope': 'preparation/byte consistency only; target ML87/SLH execution comes from native runners, not preparation smoke'}


def hosted_snapshot(path, source):
    value = read(path)
    need(value.get('source') == source and isinstance(value.get('observed_utc'), str), 'wrong hosted snapshot identity')
    runs = value.get('runs')
    need(isinstance(runs, list) and value.get('total_count') == len(runs) and len(runs) > 0, 'incomplete hosted run list')
    need(all(run.get('head_sha') == source for run in runs), 'hosted run association differs')
    derived = all(run.get('status') == 'completed' and run.get('conclusion') == 'success' for run in runs)
    need(value.get('all_hosted_gates_passed') is derived, 'hosted listed-run aggregate differs')
    return value, dict(sorted(Counter(str(run.get('status')) + '/' + str(run.get('conclusion')) for run in runs).items()))


def hosted_native(path, source):
    value = read(path)
    need(value.get('schema') == 'pon-original-native-campaign-ci-v1' and value.get('expected_head') == source,
         'wrong original native campaign identity')
    need(value.get('expected_tree') == TREES[source] and value.get('source_kind') == 'head', 'wrong original native source tree')
    source_check(value['source_after'], source)
    need(value.get('complete_success') is False and value.get('failure') == 'ORIGINAL_THREE_RUN_CAMPAIGN_FAILED',
         'original native failure must remain retained')
    need(value['build']['returncode'] == 0 and value.get('planned_complete_runs') == 3, 'original native build/plan differs')
    attempts = value.get('attempts', [])
    need(len(attempts) == 3 and [row['number'] for row in attempts] == [1, 2, 3], 'three actual native attempts required')
    need(all(row['step']['returncode'] == 101 and row['complete_success'] is False
             and row['original_criteria_met'] is False for row in attempts), 'original native 0/3 observation differs')
    return value


def initial_hosted_diagnostics():
    directory = INITIAL_ROOT / 'hosted-source-details'
    verification = read(directory / 'workspace-artifact-verification.json')
    archive_path = directory / 'workspace-head-db48af79.zip'
    zipped = raw(archive_path)
    need(verification.get('source') == INITIAL and verification.get('zip_bytes') == len(zipped)
         and verification.get('zip_sha256') == digest(zipped), 'hosted workspace ZIP differs')
    with zipfile.ZipFile(archive_path) as archive:
        inventory = verification['members']
        need(len({item['name'] for item in inventory}) == len(inventory), 'duplicate ZIP inventory')
        need({item['name'] for item in inventory} == {item.filename for item in archive.infolist() if not item.is_dir()},
             'hosted ZIP inventory incomplete')
        for item in inventory:
            data = archive.read(item['name'])
            need(len(data) == item['bytes'] and digest(data) == item['sha256'], 'hosted ZIP member changed')
        before, after = (json.loads(archive.read(name)) for name in ('source-before.json', 'source-after.json'))
        source_check(before, INITIAL)
        need(before == after, 'hosted workspace source endpoints differ')
        need(archive.read('build.exit').strip() == b'0' and archive.read('build-artifact-check.exit').strip() == b'1',
             'hosted build/check outcomes differ')
        stderr = archive.read('build-artifact-check.stderr').decode()
        need('wrong complete-workspace features for trnm-pon-node' in stderr, 'missing actual feature diagnostic')
        rows = [json.loads(line) for line in archive.read('build.jsonl').decode().splitlines() if line.strip()]
        features = {}
        for target, expected in [('trnm_pon_node', ['default', 'pq-native-openssl', 'pq-root-v3']),
                                  ('trnm_mvcc_fee', ['default', 'pq-native-openssl'])]:
            artifacts = [row for row in rows if row.get('reason') == 'compiler-artifact'
                         and row.get('target', {}).get('name') == target and row.get('target', {}).get('kind') == ['lib']]
            need(artifacts and all(row.get('features') == expected for row in artifacts), 'hosted observed features differ')
            features[target] = expected
    diagnostics = []
    for path in sorted(directory.glob('job-*.log')):
        data = raw(path)
        text = data.decode()
        if 'error: unused import: `RootStateV3`' in text and 'root_recovery_v3_native.rs:17' in text:
            diagnostics.append({'log': 'hosted-source-details/' + path.name, 'bytes': len(data), 'sha256': digest(data)})
    need(diagnostics, 'missing retained hosted unused-import diagnostic')
    return {'source': INITIAL,
            'unused_import': {'symbol': 'RootStateV3', 'line': 17, 'diagnostic_logs': diagnostics,
                              'explains_local_sigkill': False},
            'workspace': {'build_exit_code': 0, 'artifact_check_exit_code': 1, 'observed_features': features,
                          'diagnostic': stderr, 'zip_sha256': digest(zipped),
                          'scope': 'retained head artifact bytes and diagnostic; build itself succeeded'}}


def archive(source, destination):
    need(source.is_dir() and not source.is_symlink(), 'missing archive source: ' + str(source))
    index = []
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(), 'symlink in retained evidence: ' + str(path))
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        need(relative.as_posix() != 'archive-index.json', 'reserved archive-index filename in input')
        data = raw(path)
        compressed = path.suffix == '.log'
        target = destination / relative
        if compressed:
            target = target.with_name(target.name + '.gz')
        need(not target.exists(), 'archive output collision')
        encoded = gzip.compress(data, compresslevel=9, mtime=0) if compressed else data
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded)
        need((gzip.decompress(raw(target)) if compressed else raw(target)) == data, 'archive round-trip mismatch')
        index.append({'original': relative.as_posix(), 'retained': target.relative_to(destination).as_posix(),
                      'raw_bytes': len(data), 'raw_sha256': digest(data), 'retained_bytes': len(encoded),
                      'retained_sha256': digest(encoded), 'encoding': 'gzip' if compressed else 'identity'})
    need(index, 'empty evidence archive: ' + str(source))
    write(destination / 'archive-index.json', index)
    return len(index)


def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw(source))
    need(raw(destination) == raw(source), 'copied evidence changed')


def main():
    need(not OUT.exists(), 'never overwrite an earlier evidence delivery')
    environment = read(RUN / 'environment.json')
    provider = provider_check(environment)
    need(environment.get('RUSTUP_TOOLCHAIN') == '1.95.0' and environment.get('CARGO_BUILD_JOBS') == '2'
         and environment.get('CARGO_INCREMENTAL') == '0' and environment.get('CARGO_NET_OFFLINE') == 'true'
         and environment.get('RUST_TEST_THREADS') == '1', 'unexpected recovered execution environment')
    expected = plan(RUN, environment['TRNM_PQ_OPENSSL'])
    commands = records(RUN, SOURCE, expected)
    before = source_pair(RUN, SOURCE)
    summary = read(RUN / 'summary.json')
    held(summary)
    need(summary.get('source') == SOURCE and summary.get('commands_total') == 42
         and summary.get('commands_passed') == 42 and summary.get('source_unchanged') is True,
         'completed 42/42 exact-source parent summary required')
    need(summary.get('schema') == 'trnm-root-v4-recovered-exact-source-campaign', 'wrong recovered campaign schema')
    components = {version: native(RUN / ('native-' + version), version, SOURCE) for version in ('v4', 'v3')}
    need(components['v4']['passed_tests'] == 26 and components['v3']['passed_tests'] == 50, 'native totals differ')
    counts = python_counts(RUN, commands)
    need(counts.get('feature-and-registry-controls') == 15, 'actual 15 feature/registry tests required')
    defaults = {name: rust_observation(raw(RUN / (name + '.log')).decode())['passed']
                for name in ('retained-crypto-default', 'retained-release-default')}
    need(defaults == {'retained-crypto-default': 175, 'retained-release-default': 43}, 'default Rust roster changed')
    corpus = read(RUN / 'pq-source-corpus.log')
    pinned = json.loads(frozen('config/pon/pq-cross-branch-corpus-v1.json'))
    need(corpus.get('schema') == 'trnm-pq-cross-branch-check-v1' and corpus.get('exact_source_blobs') == 771
         and len(pinned['pinned_blobs']) == 771, 'actual 771-pin source corpus required')
    dependency, custody, migration = (read(RUN / (name + '.log')) for name in ('dependency-register', 'custody-review', 'migration-review'))
    for value in (dependency, custody, migration):
        held(value)
    need(dependency.get('domain_failure_bounds') == {name: None for name in DOMAINS}, 'eight bounds must remain null')
    need(dependency.get('source_file_count') == len(dependency['source_files_sha256']) == 37
         and dependency.get('hash_use_count') == 16, 'finite dependency inventory differs')
    for path, expected_hash in dependency['source_files_sha256'].items():
        need(digest(frozen(path)) == expected_hash, 'frozen dependency input differs: ' + path)
    for value, path, hash_name, algorithm in (
        (dependency, 'config/pon/pq-root-dependency-register-v3.json', 'manifest_sha256', hashlib.sha256),
        (custody, 'config/pon/pq-root-custody-review-v1.json', 'manifest_sha256', hashlib.sha256),
        (migration, 'config/pon/pq-root-migration-review-v1.json', 'manifest_sha512', hashlib.sha512)):
        need(value[hash_name] == algorithm(frozen(path)).hexdigest(), 'review manifest identity differs')
    need(migration.get('proposal_present') is False and len(custody['missing_evidence']) == 11,
         'default review incompleteness changed; revise the fixed evidence template explicitly')
    old_environment = read(OLD_RUN / 'environment.json')
    need(old_environment.get('TRNM_PQ_OPENSSL_VERSION') == '3.5.7', 'initial environment version differs')
    need(raw(OLD_RUN / 'versions-openssl.log').decode().startswith('OpenSSL 3.5.7 '), 'initial OpenSSL version log differs')
    need(raw(RUN / 'versions-openssl.log').decode().startswith('OpenSSL 3.5.9 '), 'recovered OpenSSL version log differs')
    old_plan = plan(Path('/workspace/scratch/e12ecc64880d/exact-db48af79'), '/usr/bin/openssl', corrected=False)
    old_commands = records(OLD_RUN, INITIAL, old_plan[:39])
    need(not (OLD_RUN / 'summary.json').exists() and not (OLD_RUN / 'source-after.json').exists(),
         'do not invent or silently substitute initial parent completion records')
    source_check(read(OLD_RUN / 'source-before.json'), INITIAL)
    old_components = {version: native(OLD_RUN / ('native-' + version), version, INITIAL) for version in ('v4', 'v3')}
    old_clippy = raw(OLD_RUN / 'workspace-clippy.log')
    need(b'(signal: 9, SIGKILL: kill)' in old_clippy and b'could not compile `trnm-pon-node`' in old_clippy,
         'initial compiler SIGKILL observation missing')
    need(not (OLD_RUN / 'diff-check.log').exists(), 'unexpected initial diff-check execution evidence')
    hosted, hosted_counts = hosted_snapshot(BASE / 'hosted-source-0d999240.json', SOURCE)
    old_hosted, _ = hosted_snapshot(BASE / 'hosted-source-db48af79.json', INITIAL)
    prior = read(INITIAL_ROOT / 'hosted-prior-a44344b2.json')
    diagnostics = initial_hosted_diagnostics()
    old_native = hosted_native(INITIAL_ROOT / 'hosted-source-details/native-campaign-result-db48af79.json', INITIAL)
    corrected_details = BASE / 'hosted-corrected-details'
    corrected_native = hosted_native(corrected_details / 'native-campaign-result-0d999240.json', SOURCE)
    corrected_log = raw(corrected_details / 'job-129060656332.log')
    need(len(corrected_log) == 208100 and digest(corrected_log) == CORRECTED_JOB_SHA256,
         'corrected hosted failure log differs')
    selected_artifact = read(corrected_details / 'native-artifact-selected/artifact-readback.json')
    need(selected_artifact['source'] == SOURCE and selected_artifact['artifact_id'] == 13659748476,
         'wrong selected hosted artifact')
    need(selected_artifact['zip_sha256'] == '06fdbd610d0c96982cf447fdbb30d89b028dfa2013c9a9f890bbaaa76e4962a9',
         'wrong full downloaded artifact digest')
    for item in selected_artifact['selected_raw_members']:
        data = raw(corrected_details / 'native-artifact-selected' / item['path'])
        need(len(data) == item['bytes'] and digest(data) == item['sha256'], 'selected raw member differs')
    for projection, attempt in zip(selected_artifact['report_projection']['reports'], corrected_native['attempts']):
        need(projection['raw_sha256'] == attempt['report_sha256'], 'large report projection source differs')
    runtime_after = read(BASE / 'runtime-after-campaign.json')
    warning_log = raw(RUN / 'v2-journal-native.log').decode()
    resource_warnings = {
        'suite': 'v2-journal-native', 'suite_exit_code': 0,
        'suite_tests': counts['v2-journal-native'],
        'resource_warning_lines': sum('ResourceWarning:' in line for line in warning_log.splitlines()),
        'unclosed_sqlite_database_warning_observed': 'ResourceWarning: unclosed database' in warning_log,
        'every_warning_uniquely_attributed': False,
        'allocation_tracebacks_collected': False,
        'source_inspection': {
            'fixture_file': 'formal/pon-nakamoto-v1/test_pq_root_recovery_journal_native_v2.py',
            'fixture_uses_transaction_contexts_without_explicit_connection_close': True,
            'owner_file': 'formal/pon-nakamoto-v1/pq_root_recovery_journal_v2.py',
            'owner_normal_database_path_has_finally_close': True,
            'owner_initial_pragma_calls_precede_that_try_finally': True,
        },
        'scope': 'Retained resource-lifetime warnings and source review. No unique causal attribution, data-corruption finding, resource-exhaustion finding or zero-warning claim follows.',
    }
    need(hosted['all_hosted_gates_passed'] is False, 'corrected source retains a failed original native campaign')
    old_qualification = json.loads(frozen('evidence/pq-root-native-v3-20261109/qualification-record.json'))
    template = raw(BASE / 'evidence_readme_recovered_template.md').decode()
    # Validate all required observations before creating an output tree.
    OUT.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.pq-root-v4-assembling-', dir=OUT.parent))
    archive_counts = {}
    for source, name in ((RUN, 'attempt-0d999240'), (OLD_RUN, 'attempt-db48af79'),
                         (INITIAL_ROOT / 'development', 'development'),
                         (INITIAL_ROOT / 'hosted-source-details', 'hosted-source-details'),
                         (corrected_details, 'hosted-corrected-details'), (BASE / 'preparation', 'preparation')):
        archive_counts[name] = archive(source, stage / name)
    for source, name in (
        (BASE / 'run_campaign_v4_recovered.py', 'run_campaign_v4_recovered.py'),
        (INITIAL_ROOT / 'run_campaign_v4.py', 'run_campaign_v4.py'),
        (BASE / 'fetch-ready.json', 'fetch-ready.json'), (BASE / 'provider.env', 'provider.env'),
        (BASE / 'runtime-after-campaign.json', 'runtime-after-campaign.json'),
        (BASE / 'delivery-packaging-review.json', 'delivery-packaging-review.json'),
        (BASE / 'hosted-source-db48af79.json', 'hosted-source-db48af79.json'),
        (BASE / 'hosted-source-0d999240.json', 'hosted-source-0d999240.json'),
        (INITIAL_ROOT / 'hosted-prior-a44344b2.json', 'hosted-prior-a44344b2.json'),
        (Path(__file__), 'assemble_v4_evidence_recovered.py'),
        (BASE / 'evidence_readme_recovered_template.md', 'evidence_readme_recovered_template.md')):
        copy_file(source, stage / name)
    initial_attempt = {
        'source': INITIAL, 'source_tree': TREES[INITIAL],
        'execution_state': 'INCOMPLETE_WITH_COMPILER_FAILURE_OBSERVATION',
        'planned_commands_from_retained_harness': len(old_plan), 'recorded_command_outcomes': len(old_commands),
        'recorded_exit_zero_commands': len(old_commands), 'recorded_nonzero_exits': [],
        'complete_campaign_success_observed': False, 'parent_summary_recorded': False,
        'parent_source_before_recorded': True, 'parent_source_after_recorded': False,
        'parent_source_before_after_equal': None, 'recorded_command_log_hashes_verified': True,
        'component_observations': old_components,
        'workspace_clippy': {'process_returncode': None, 'compiler_process_signal': 9, 'compiler_process_signal_name': 'SIGKILL',
                            'termination_cause': None, 'original_log': 'attempt-db48af79/workspace-clippy.log',
                            'retained_log': 'attempt-db48af79/workspace-clippy.log.gz', 'encoding': 'gzip',
                            'log_bytes': len(old_clippy), 'post_recovery_log_sha256': digest(old_clippy)},
        'diff_check': {'execution_state': 'EXECUTION_UNOBSERVED', 'process_returncode': None},
        'environment': old_environment,
        'corrections': ['unused-import cleanup diagnosed by a separate hosted run',
                        'exact per-crate workspace/ancestry feature allowlists and feature reporting',
                        'AST negative controls and mandatory repository-truth execution', 'reviewed source/hash pins'],
        'local_sigkill_cause_established': False,
    }
    blockers = {
        'independent_custody_and_recovery': 'Independent operator/device/backup/recovery, complete key/epoch records and authenticated operational review remain missing.',
        'all_currentness_state_restored_together': 'A sufficiently fresh authenticated pin must survive the common restore set; supplied immutable bytes do not establish that independence.',
        'actual_external_effects': 'M15/FinalUse admission, real payment/API/resource effects, provider lifecycle/request authentication and actual reorg compensation remain unconnected.',
        'algorithm_replacement': 'Migration review does not authorize a runtime switch; explicit implementation, actual current authority, successor possession and security arguments remain required.',
        'lifetime_risk_and_composition': 'All eight actual bounds remain null; complete populations, shared query/preprocessing/advice scope and whole-chain bad-event coverage remain open.',
    }
    record = {
        'schema': 'trnm-root-continuation-v4-delivery-evidence-v2',
        'pull_request': 'https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/837',
        'base_delivery_commit': '57e6c17ae2fa8a9cc547e271f34d90ef09115f04',
        'source_commit': SOURCE, 'source_tree': TREES[SOURCE],
        'source_tracked_entries': before['tracked_entries'], 'source_tracked_bytes': before['tracked_bytes'],
        'source_before_and_after_equal': True, 'local_execution_state': 'COMPLETE_SUCCESS_OBSERVED',
        'local_commands_planned': len(expected), 'local_commands_passed': len(commands), 'local_commands_total': len(commands),
        'exact_command_plan_and_hashes_verified': True, 'native_component_observations': components,
        'native_component_execution_passed': all(item['component_execution_passed'] for item in components.values()),
        'python_suite_tests': counts, 'retained_default_rust_tests': defaults,
        'strict_workspace_all_targets_all_features_clippy_passed': next(row for row in commands if row['name'] == 'workspace-clippy')['exit_code'] == 0,
        'count_overlap': 'Default crypto includes the V3 structural tests; counts are not independent security properties.',
        'source_corpus_observation': corpus, 'dependency_snapshot': dependency, 'custody_review': custody, 'migration_review': migration,
        'domain_failure_bounds': dependency['domain_failure_bounds'], 'open_obligations': dependency['open_obligations'],
        'blockers': {name: {'status': 'HOLD', 'missing': text} for name, text in blockers.items()},
        'status': 'HOLD', 'actual_lifetime_failure_bound': None,
        'initial_attempt': initial_attempt, 'initial_hosted_diagnostics': diagnostics,
        'initial_candidate_hosted_snapshot': old_hosted, 'source_hosted_snapshot': hosted,
        'prior_source_hosted_snapshot': prior,
        'prior_hosted_original_native_campaign': old_qualification['hosted_original_native_campaign'],
        'initial_candidate_hosted_original_native_campaign': old_native,
        'corrected_hosted_original_native_campaign': corrected_native,
        'corrected_hosted_selected_artifact_readback': selected_artifact,
        'corrected_hosted_original_native_failure_cause': None,
        'all_hosted_gates_passed': hosted['all_hosted_gates_passed'], 'all_required_hosted_gates_verified': False,
        'provider_preparation_observation': provider,
        'post_campaign_runtime_observation': runtime_after,
        'delivery_packaging_review': read(BASE / 'delivery-packaging-review.json'),
        'retained_resource_warning_observation': resource_warnings,
        'environment_comparison': {'initial_openssl': '3.5.7', 'corrected_openssl': '3.5.9', 'same_environment_claimed': False,
                                   'scope': 'different host/build environment and provider version; no isolated causal or performance comparison'},
        'development_logs_scope': 'Pre-freeze preparation, fetch and development observations are retained separately from the 42-command frozen-source campaign.',
        'evidence_scope': 'Recorded local component execution, observed source endpoints and dated hosted readbacks. Signatures/fixtures do not establish real effects, independent custody or actual risk bounds.',
    }
    record.update({name: False for name in FALSE_QUALIFICATION})
    held(record)
    write(stage / 'qualification-record.json', record)
    write(stage / 'initial-attempt-recovery-observation.json', initial_attempt)
    write(stage / 'exact-command-plan.json', [{'name': name, 'argv': argv} for name, argv in expected])
    write(stage / 'packaging-observation.json', {
        'schema': 'trnm-root-v4-evidence-byte-check-v1', 'source': SOURCE,
        'recorded_command_log_hashes_verified': True, 'native_rosters_reparsed_from_raw_logs': True,
        'gzip_roundtrips_verified': True, 'archive_file_counts': archive_counts,
        'initial_unrecorded_log_hash_scope': 'post-recovery bytes; no fabricated command-end receipt',
        'execution_provenance_authenticated': False, 'security_properties_proved_by_packaging': False,
        'recovered_harness_sha256': digest(raw(BASE / 'run_campaign_v4_recovered.py')),
        'packager_sha256': digest(raw(Path(__file__))),
    })
    native_rows = '\n'.join('| ' + version.upper() + ' / ' + name + ' | ' + str(item['passed']) + ' |'
                            for version, component in components.items() for name, item in component['observations'].items())
    python_rows = '\n'.join('| ' + name + ' | ' + str(count) + ' |' for name, count in counts.items())
    replacements = {
        'SOURCE': SOURCE, 'TREE': TREES[SOURCE], 'COMMANDS': str(len(commands)),
        'ENTRIES': str(before['tracked_entries']), 'BYTES': str(before['tracked_bytes']),
        'NATIVE_ROWS': native_rows, 'PYTHON_ROWS': python_rows,
        'CRYPTO_DEFAULT': str(defaults['retained-crypto-default']), 'RELEASE_DEFAULT': str(defaults['retained-release-default']),
        'PINS': str(corpus['exact_source_blobs']), 'SOURCE_FILES': str(dependency['source_file_count']),
        'HASH_GROUPS': str(dependency['hash_use_count']), 'SNAPSHOT': dependency['declared_source_snapshot_sha256'],
        'CUSTODY_MISSING': str(len(custody['missing_evidence'])), 'HOSTED_TIME': hosted['observed_utc'],
        'HOSTED_COUNTS': ', '.join(name + ': ' + str(count) for name, count in hosted_counts.items()),
    }
    for key, value in replacements.items():
        template = template.replace('{{' + key + '}}', value)
    need(not re.search(r'\{\{[^{}]+\}\}', template), 'unfilled README template field')
    (stage / 'README.md').write_text(template)
    files = [{'path': path.relative_to(stage).as_posix(), 'bytes': path.stat().st_size, 'sha256': digest(raw(path))}
             for path in sorted(stage.rglob('*')) if path.is_file()]
    write(stage / 'archive-verification.json', {
        'schema': 'trnm-root-v4-retained-byte-manifest-v1', 'source': SOURCE, 'files': files,
        'self_excluded': 'archive-verification.json', 'scope': 'retained bytes only; no authenticated execution provenance',
    })
    for item in files:
        data = raw(stage / item['path'])
        need(len(data) == item['bytes'] and digest(data) == item['sha256'], 'final retained bytes changed')
    need(not OUT.exists(), 'output appeared while packaging; preserve the staging directory')
    os.rename(stage, OUT)
    print(json.dumps({'output': str(OUT), 'source_commit': SOURCE, 'local_commands': len(commands),
                      'native_v4_tests': components['v4']['passed_tests'], 'native_v3_tests': components['v3']['passed_tests'],
                      'corrected_hosted_original_campaign': '0/3', 'status': 'HOLD'}, sort_keys=True))


if __name__ == '__main__':
    main()
