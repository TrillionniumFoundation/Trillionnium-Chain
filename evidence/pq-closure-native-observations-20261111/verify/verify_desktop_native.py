#!/usr/bin/env python3
"""Verify retained C1 desktop native observations without rerunning workloads.

This checks consistency and immutable Git bindings of recorded evidence. It does
not attest the host, certify a complete runtime route, or qualify cryptography.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

C1 = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
TREE = 'f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6'
BRANCH = 'fix/chain-pq-closure-20261111-d4d2'
REPO_PATH = '/home/qian-qi/work/chain-pq-closure-20261111-d4d2'
OUTPUT_PATH = REPO_PATH + '-validation-c09dbbe9921d-01'
TARGET_PATH = '/data/chain-pq-closure-20261111-d4d2-cargo-target-c09dbbe9921d-01'
PROVIDER_PATH = ('/home/qian-qi/chain-stark-route-validation-7e8b/'
                 'provider-clippy-eeeaafbc742d-retry01/'
                 'trnm-pq-provider-3.5.9.wUXuiklK/install')
RUNNER_SHA = 'e5a378b43130e888d58b021ed58dc28f4c560c1075d8e08b7db79313765bc45e'
EXPECTED_PLAN_SHA = 'f83cfaa68c52e9e05e0576158ba5170635482168bb7ee5090d4bc5d158713d2c'
KNOWN_TIMEOUT_COMPLETIONS = {'root-effect-readback-v4-native': 4, 'root-witness-v5-native': 6}
COUNTS = {'account-profile-boundary': 4, 'account-development-scope': 5,
          'root-recovery-v3-native': 20, 'recovery-floor-v4-native': 9,
          'root-effect-readback-v4-native': 14, 'root-budget-v4-native': 6,
          'root-witness-v5-native': 17, 'root-witness-v5-durable-native': 12,
          'node-account-scope': 4, 'node-all-pq-profile-settlement': 1,
          'tls-full-spki-1': 1, 'tls-full-spki-2': 1, 'tls-full-spki-3': 1,
          'node-qtx1-recovery': 1, 'distinct-invalid-work': 1}
COMMANDS = ['preflight', 'rustc-version', 'cargo-version', 'openssl-version',
            'metadata-default', 'metadata-all-features', 'metadata-fuzz', 'fmt',
            'repository-contract', 'distributed-source-inventory', 'pq-research-integration',
            *COUNTS, 'strict-workspace-clippy']
IDENTITY = {'commit': C1, 'tree': TREE, 'branch': BRANCH, 'status': ''}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def native_lines(data):
    text = data.decode('utf-8')
    found = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (.+)$', text, re.M)
    return text, [name for name, result in found if result == 'ok'], found


def git_verification(root, snapshot):
    command = ['git', '--no-replace-objects', '--no-optional-locks', '-C', str(root)]
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1',
                       GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0')
    tree = subprocess.check_output(command + ['rev-parse', C1 + '^{tree}'], env=environment).decode().strip()
    require(tree == TREE, 'local Git C1 tree')
    entries = subprocess.check_output(command + ['ls-tree', '-rlz', '--full-tree', C1], env=environment).split(b'\0')
    expected = []
    for entry in filter(None, entries):
        meta, path = entry.split(b'\t', 1)
        mode, kind, oid, size = meta.split()
        require(kind == b'blob', 'Git tree contains nonblob')
        expected.append((path.decode(), mode.decode(), oid.decode(), int(size)))
    require(expected == [(r['path'], r['mode'], r['git_blob'], r['bytes'])
                         for r in snapshot['files']], 'retained snapshot/Git tree entries differ')
    with subprocess.Popen(command + ['cat-file', '--batch'], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment) as reader:
        try:
            for row in snapshot['files']:
                reader.stdin.write((row['git_blob'] + '\n').encode())
                reader.stdin.flush()
                require(reader.stdout.readline().split() ==
                        [row['git_blob'].encode(), b'blob', str(row['bytes']).encode()], 'Git blob header')
                left, digest = row['bytes'], hashlib.sha256()
                while left:
                    data = reader.stdout.read(min(1024 * 1024, left))
                    require(data, 'truncated Git blob')
                    digest.update(data)
                    left -= len(data)
                require(reader.stdout.read(1) == b'\n' and digest.hexdigest() == row['sha256'],
                        'retained SHA256 differs from actual Git blob: ' + row['path'])
            reader.stdin.close()
            require(reader.wait(timeout=30) == 0, 'Git blob reader failed')
        except BaseException:
            reader.kill()
            reader.wait(timeout=30)
            raise
    return {'all_git_blobs_sha256_recomputed': True, 'files': len(expected),
            'bytes': sum(r['bytes'] for r in snapshot['files'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--expected-plan', type=Path,
                        default=Path(__file__).with_name('expected-native-plan-c09dbbe992.json'))
    parser.add_argument('--git-source', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    expected_plan_bytes = args.expected_plan.read_bytes()
    require(sha(expected_plan_bytes) == EXPECTED_PLAN_SHA, 'independent fixed source-plan binding')
    expected_plan = decode(expected_plan_bytes)
    require(expected_plan['source'] == {'commit': C1, 'tree': TREE}
            and expected_plan['runner_sha256'] == RUNNER_SHA
            and expected_plan['native_workload_executed'] is False, 'expected-plan generation scope')
    receipt = decode(args.receipt.read_bytes())
    require(receipt['schema'] == 'trnm-native-archive-receipt-v1', 'archive receipt schema')
    archive_bytes = args.archive.read_bytes()
    require(receipt['source'] == C1 and receipt['bytes'] == len(archive_bytes)
            and receipt['sha256'] == sha(archive_bytes), 'archive receipt binding')
    raw, modes = {}, {}
    with tarfile.open(args.archive, 'r:xz') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(member.isfile() and not name.is_absolute() and '..' not in name.parts
                    and str(name) == member.name and member.name not in raw,
                    'nonregular/unsafe/duplicate archive member')
            raw[member.name] = archive.extractfile(member).read()
            modes[member.name] = member.mode
    require(len(raw) == receipt['members'], 'archive member count')
    manifest_path = 'native/export-file-manifest.json'
    require(len(raw[manifest_path]) == receipt['manifest']['bytes']
            and sha(raw[manifest_path]) == receipt['manifest']['sha256']
            and modes[manifest_path] == receipt['manifest']['mode'], 'manifest/receipt binding')
    manifest = decode(raw[manifest_path])
    require(manifest['schema'] == 'trnm-native-raw-export-v1', 'export manifest schema')
    require(set(raw) == set(manifest['files']) | {manifest_path}, 'unaccounted archive member')
    for name, expected in manifest['files'].items():
        data = raw[name]
        require(len(data) == expected['bytes'] and sha(data) == expected['sha256']
                and modes[name] == expected['mode'], 'member bytes/mode mismatch: ' + name)
    require(manifest['source'] == C1 and manifest['original_logs_modified'] is False
            and manifest['cargo_target_included'] is False
            and manifest['whole_chain_quantum_security_qualified'] is False, 'manifest scope')
    require(sha(raw['reproduction/desktop_validate.py']) == RUNNER_SHA, 'original runner changed')
    def doc(name):
        return decode(raw['native/' + name])
    source_before, source_after = doc('source-before.json'), doc('source-after.json')
    require(source_before['schema'] == source_after['schema'] == 'trnm-desktop-exact-source-v1', 'source schema')
    require(raw['native/source-before.json'] == raw['native/source-after.json'], 'whole-group source changed')
    require({k: source_before[k] for k in IDENTITY} == IDENTITY, 'source identity')
    require(source_before['all_actual_bytes_compared_with_git_blobs'] is True
            and source_before['tracked_entries'] == len(source_before['files']) == 27912
            and source_before['tracked_bytes'] == sum(r['bytes'] for r in source_before['files']) == 2554106689,
            'complete tracked source scope')
    require(len({r['path'] for r in source_before['files']}) == 27912, 'duplicate source file')
    source_rows = {r['path']: r for r in source_before['files']}
    require(len(expected_plan['source_inputs']) == 9
            and all(source_rows[row['path']] == row for row in expected_plan['source_inputs']),
            'independent named-roster source bytes differ')
    require(raw['native/provider-before.json'] == raw['native/provider-after.json'], 'provider changed')
    provider = doc('provider-before.json')
    require(provider['provider'] == PROVIDER_PATH, 'observed provider location changed')
    require(set(provider['files']) == {'bin/openssl', 'include/openssl/opensslv.h',
            'include/openssl/configuration.h', 'lib/libcrypto.a', 'lib/libssl.a'}, 'provider roster')
    plan, summary = doc('plan.json'), doc('summary.json')
    require(summary['schema'] == 'trnm-desktop-pq-validation-v1', 'group summary schema')
    require(plan['source_directory'] == REPO_PATH and plan['output_directory'] == OUTPUT_PATH
            and plan['target_directory'] == TARGET_PATH and summary['output_directory'] == OUTPUT_PATH
            and summary['target_directory'] == TARGET_PATH, 'actual source/output/target scope')
    require(plan['commit'] == C1 and plan['runner']['sha256'] == RUNNER_SHA
            and plan['runner']['bytes'] == len(raw['reproduction/desktop_validate.py']), 'plan source/runner')
    require([r['name'] for r in plan['commands']] == COMMANDS and len(COMMANDS) == 27
            and sum(COUNTS.values()) == 97, 'original plan roster')
    require(plan['commands'] == expected_plan['commands'], 'argv/limits/rosters differ from fixed C1 runner/source')
    require(summary['source'] == C1 and summary['complete'] is True
            and summary['source_unchanged'] is True and summary['provider_unchanged'] is True
            and summary['not_started'] == [] and summary['fatal'] is None, 'group not completely observed')
    require(summary['status'] == 'HOLD_NO_GO' and summary['production_activation'] is False
            and summary['whole_chain_quantum_security_qualified'] is False
            and summary['native_run_is_not_hosted_ci'] is True, 'qualification/source scope changed')
    require([r['name'] for r in summary['commands']] == COMMANDS, 'command result roster')
    environment = plan['environment']
    required_environment = {
        'PATH': '/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
        'RUSTUP_TOOLCHAIN': '1.95.0', 'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0',
        'CARGO_TARGET_DIR': TARGET_PATH, 'CARGO_NET_OFFLINE': 'true',
        'RUSTC': '/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc',
        'OPENSSL_DIR': PROVIDER_PATH, 'OPENSSL_STATIC': '1',
        'OPENSSL_LIB_DIR': PROVIDER_PATH + '/lib', 'OPENSSL_INCLUDE_DIR': PROVIDER_PATH + '/include',
        'OPENSSL_NO_VENDOR': '1', 'OPENSSL_CONF': '/dev/null',
        'OPENSSL_MODULES': PROVIDER_PATH + '/lib/ossl-modules',
        'TRNM_PQ_OPENSSL': PROVIDER_PATH + '/bin/openssl', 'TRNM_PQ_OPENSSL_VERSION': '3.5.9',
        'TRNM_PQ_OPENSSL_SHA256': provider['files']['bin/openssl']['sha256'],
    }
    require(all(environment.get(key) == value for key, value in required_environment.items()),
            'actual provider/toolchain/target path binding')
    require(environment['CARGO_BUILD_JOBS'] == '2' and environment['CARGO_INCREMENTAL'] == '0'
            and environment['CARGO_NET_OFFLINE'] == 'true' and environment['RUSTUP_TOOLCHAIN'] == '1.95.0'
            and environment['OPENSSL_STATIC'] == '1'
            and environment['TRNM_PQ_OPENSSL_SHA256'] == provider['files']['bin/openssl']['sha256'],
            'runtime/toolchain environment')
    require(all(not v for k, v in environment.items() if k.startswith('CARGO_PROFILE_') or k in
                ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')),
            'profile/compiler override')
    native, failed = [], []
    for declared, row in zip(plan['commands'], summary['commands']):
        name = row['name']
        require(row['schema'] == 'trnm-desktop-command-v1' and row['cwd'] == REPO_PATH,
                'command schema/source directory')
        require(row == doc(name + '.receipt.json'), 'summary/receipt mismatch: ' + name)
        require(all(row[k] == declared[k] for k in ('name', 'argv', 'timeout_seconds', 'expected_tests')),
                'plan/command mismatch: ' + name)
        require(row['source_before'] == IDENTITY and row['source_after'] == IDENTITY
                and row['environment'] == environment and row['direct_child_reaped'] is True,
                'command source/environment/cleanup: ' + name)
        for stream in ('stdout', 'stderr'):
            ref = row[stream]
            require(ref['name'] == name + '.' + stream + '.log', 'stream path')
            data = raw['native/' + ref['name']]
            require(len(data) == ref['bytes'] and sha(data) == ref['sha256'], 'stream hash: ' + name)
        if row['passed']:
            require(type(row['exit_code']) is int and row['exit_code'] == 0
                    and row['timed_out'] is False and row['exception'] is None, 'false successful receipt')
        else:
            failed.append(name)
            require(row['exit_code'] != 0 or row['timed_out'] or row['exception'] is not None
                    or 'native_result_error' in row or row.get('expected_version_observed') is False,
                    'unexplained failed receipt')
        version_patterns = {'rustc-version': r'^release: 1\.95\.0$',
                            'cargo-version': r'^cargo 1\.95\.0 \(',
                            'openssl-version': r'^OpenSSL 3\.5\.9\b'}
        if name in version_patterns:
            require(row['passed'] is True and row['expected_version_observed'] is True
                    and re.search(version_patterns[name], raw['native/' + name + '.stdout.log'].decode(), re.M),
                    'expected version not actually observed: ' + name)
        if row['timed_out']:
            require(row['exit_code'] in (-15, -9) and 'owned-group-SIGTERM' in row['cleanup']
                    and row['passed'] is False and row['elapsed_seconds'] >= row['timeout_seconds'],
                    'timeout evidence changed')
        if name in KNOWN_TIMEOUT_COMPLETIONS:
            require(row['timed_out'] is True and row['timeout_seconds'] == 1200
                    and row['exit_code'] == -15 and row['exception'] is None
                    and row['cleanup'] == ['owned-group-SIGTERM'] and row['passed'] is False,
                    'known original timeout was reclassified: ' + name)
        if name not in COUNTS:
            require(row['expected_tests'] is None, 'unexpected native roster')
            continue
        expected = row['expected_tests']
        require(len(expected) == len(set(expected)) == COUNTS[name], 'native planned count')
        text, completed, observations = native_lines(raw['native/' + name + '.stdout.log'])
        require(len(completed) == len(set(completed)) and set(completed) <= set(expected), 'partial named set')
        if name in KNOWN_TIMEOUT_COMPLETIONS:
            require(completed == sorted(expected)[:KNOWN_TIMEOUT_COMPLETIONS[name]],
                    'known completed original names changed: ' + name)
        if row['passed']:
            terminal = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                                  r'(\d+) measured; (\d+) filtered out; finished in .+$', text, re.M)
            require(len(terminal) == 1 and terminal[0][:5] == ('ok', str(COUNTS[name]), '0', '0', '0'),
                    'native successful terminal result')
            require(len(observations) == COUNTS[name] and set(completed) == set(expected)
                    and re.findall(r'^running (\d+) tests?$', text, re.M) == [str(COUNTS[name])],
                    'native successful named completions')
            require(row['native_observation'] == {'passed': COUNTS[name], 'tests': sorted(expected),
                    'filtered_out': int(terminal[0][5])}, 'native receipt projection')
        else:
            require('native_observation' not in row, 'failed command promoted to completed native target')
        native.append({'target': name, 'expected': COUNTS[name], 'target_passed': row['passed'],
                       'completed_ok_names': completed,
                       'remaining_without_ok': sorted(set(expected) - set(completed)),
                       'timed_out': row['timed_out'], 'exit_code': row['exit_code'],
                       'elapsed_seconds': row['elapsed_seconds'], 'timeout_seconds': row['timeout_seconds']})
    require('root-effect-readback-v4-native' in failed and 'root-witness-v5-native' in failed,
            'original observed timeouts not retained')
    passed_total = sum(r['expected'] for r in native if r['target_passed'])
    completed_total = sum(len(r['completed_ok_names']) for r in native)
    require(summary['all_selected_commands_passed'] is False
            and manifest['all_selected_commands_passed'] is False
            and receipt['all_selected_commands_passed'] is False
            and receipt['whole_chain_quantum_security_qualified'] is False
            and receipt['failed_commands'] == failed and receipt['not_started'] == []
            and receipt['native_tests_observed'] == passed_total, 'original failed group upgraded')
    require(manifest['complete'] is True and all(manifest[k] is True for k in
            ('source_unchanged', 'provider_unchanged')) and all(receipt[k] is True for k in
            ('source_unchanged', 'provider_unchanged', 'all_archived_bytes_verified')),
            'export source/scope mismatch')
    clippy = summary['commands'][-1]
    require(clippy['argv'][-6:] == ['--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']
            and '--locked' in clippy['argv'] and '--offline' in clippy['argv'], 'strict Clippy weakened')
    git_result = git_verification(args.git_source, source_before) if args.git_source else None
    result = {'schema': 'TRNM-C1-DESKTOP-EVIDENCE-VERIFICATION1', 'verified': True,
              'source': IDENTITY, 'archive_sha256': receipt['sha256'], 'raw_members': len(raw),
              'original_group_complete': True, 'original_group_passed': False,
              'failed_commands': failed, 'strict_clippy_passed': clippy['passed'],
              'planned_native_executions': 97, 'passed_complete_target_executions': passed_total,
              'actual_named_ok_including_partial_targets': completed_total,
              'partial_ok_is_not_a_target_pass': True, 'native_targets': native,
              'git_blob_verification': git_result, 'independent_security_property_count': None,
              'host_or_execution_attestation_claimed': False,
              'whole_chain_pq_qualified': False, 'production_activation': False}
    if args.output:
        with args.output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'native_targets'}, sort_keys=True))


if __name__ == '__main__':
    main()
