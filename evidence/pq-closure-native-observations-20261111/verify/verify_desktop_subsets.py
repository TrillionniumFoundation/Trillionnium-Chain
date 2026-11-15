#!/usr/bin/env python3
"""Offline checks of the retained C1 readback and witness-V5 subset packets.

This never runs the native programs. It verifies recorded observations, including
failed or timed-out subsets; it does not turn a subset into the original aggregate
budget pass. ELF bytes and a host/execution attestation are not in these packets.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

C1 = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
TREE = 'f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6'
REPO = '/home/qian-qi/work/chain-pq-closure-20261111-d4d2'
ORIGINAL = REPO + '-validation-c09dbbe9921d-01'
TARGET = '/data/chain-pq-closure-20261111-d4d2-cargo-target-c09dbbe9921d-01'
IDENTITY = {'commit': C1, 'tree': TREE, 'branch': 'fix/chain-pq-closure-20261111-d4d2', 'status': ''}
ORIGINAL_RUNNER_SHA = 'e5a378b43130e888d58b021ed58dc28f4c560c1075d8e08b7db79313765bc45e'
ORIGINAL_VERIFIER_SHA = '02b62d0a6b206ba35fb6c66e85b3a46bdfc2c03ea9a348771eef29b3cb5aae4c'
EXPECTED_PLAN_SHA = 'f83cfaa68c52e9e05e0576158ba5170635482168bb7ee5090d4bc5d158713d2c'
CONFIG = {
    'readback': {
        'target': 'root-effect-readback-v4-native', 'skip': 4, 'remaining': 10,
        'stem': 'trnm-readback-subset', 'runner': 'desktop_readback_subset.py',
        'runner_sha': '4e6e909103edeacb6e1294bcd14a7857c2a6963c4d660a3dc7e5380f645144dd',
        'exe': TARGET + '/debug/deps/root_effect_readback_v4_native-746f335cb9f2c139',
        'exe_sha': 'ec8c0f2f1b111d6ac0d3dd9cb2bccf84e8db77b226cf156012a48585a7ac5802',
        'exe_bytes': 248562696,
        'output': '/data/chain-pq-closure-20261111-d4d2-readback-subset-c09dbbe9921d-01',
    },
    'witness-v5': {
        'target': 'root-witness-v5-native', 'skip': 6, 'remaining': 11,
        'stem': 'trnm-witness-v5-subset', 'runner': 'desktop_witness_v5_subset.py',
        'runner_sha': '6ca95aff51f062268be10fc402bfc0014c74ba09865ccff2ca6480337d20229e',
        'exe': TARGET + '/debug/deps/root_witness_v5_native-fb785672eb81b96f',
        'exe_sha': '91908655f8d81365fe6fdb4611d61b5014561a0eafe80b6922469772b992ff1a',
        'exe_bytes': 248613192,
        'output': '/data/chain-pq-closure-20261111-d4d2-witness-v5-subset-c09dbbe9921d-01',
    },
}


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


def file_identity(path):
    digest, size = hashlib.sha256(), 0
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(part)
            size += len(part)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def member_identity(packet, name):
    return {'bytes': len(packet['raw'][name]), 'sha256': sha(packet['raw'][name]),
            'mode': packet['modes'][name]}


def check_member_pin(pin, packet, name, labelled=False):
    expected = member_identity(packet, name)
    if labelled:
        expected = {'member': name, **expected}
    require(pin == expected, 'retained member pin: ' + name)


def check_file_pin(pin, path, archive_receipt=None):
    actual = file_identity(path)
    require(all(pin[key] == value for key, value in actual.items()), 'external retained file pin')
    require(isinstance(pin['path'], str) and pin['path'].startswith('/')
            and type(pin['mode']) is int and 0 <= pin['mode'] <= 0o7777, 'external pin shape')
    if archive_receipt is not None:
        require(pin['path'] == archive_receipt['archive'] and pin['mode'] == archive_receipt['mode'],
                'original archive location/mode observation')
    # A transported local file need not retain the original host permission mode.


def load_packet(archive_path, receipt_path, prefix, original=False):
    receipt = decode(Path(receipt_path).read_bytes())
    require(receipt['schema'] == ('trnm-native-archive-receipt-v1' if original
                                  else 'trnm-observation-archive-receipt-v1'), 'archive receipt schema')
    actual = file_identity(archive_path)
    require(all(receipt[key] == value for key, value in actual.items()), 'archive byte binding')
    require(receipt['all_archived_bytes_verified'] is True, 'producer archive verification flag')
    raw, modes = {}, {}
    with tarfile.open(archive_path, 'r:xz') as archive:
        for entry in archive:
            name = PurePosixPath(entry.name)
            require(entry.isfile() and not name.is_absolute() and '..' not in name.parts
                    and str(name) == entry.name and entry.name not in raw, 'unsafe/nonregular/duplicate member')
            raw[entry.name] = archive.extractfile(entry).read()
            modes[entry.name] = entry.mode
    packet = {'raw': raw, 'modes': modes, 'receipt': receipt,
              'archive_path': Path(archive_path), 'receipt_path': Path(receipt_path), 'prefix': prefix}
    manifest_name = prefix + '/export-file-manifest.json'
    check_member_pin(receipt['manifest'], packet, manifest_name)
    manifest = decode(raw[manifest_name])
    require(manifest['schema'] == ('trnm-native-raw-export-v1' if original
                                   else 'trnm-observation-raw-export-v1'), 'manifest schema')
    require(len(raw) == receipt['members']
            and set(raw) == set(manifest['files']) | {manifest_name}, 'manifest member coverage')
    for name, pin in manifest['files'].items():
        check_member_pin(pin, packet, name)
    packet['manifest'] = manifest
    packet['summary'] = decode(raw[prefix + '/summary.json'])
    packet['plan'] = decode(raw[prefix + '/plan.json'])
    return packet


def load_expected(path):
    data = Path(path).read_bytes()
    require(sha(data) == EXPECTED_PLAN_SHA, 'independent C1 expected-plan bytes')
    expected = decode(data)
    require(expected['source'] == {'commit': C1, 'tree': TREE}
            and expected['runner_sha256'] == ORIGINAL_RUNNER_SHA
            and expected['native_workload_executed'] is False, 'expected-plan scope')
    return expected


def verify_original(args):
    require(file_identity(args.original_verifier)['sha256'] == ORIGINAL_VERIFIER_SHA,
            'fixed original verifier changed')
    argv = [sys.executable, '-I', '-B', str(args.original_verifier),
            '--archive', str(args.original_archive), '--receipt', str(args.original_receipt),
            '--expected-plan', str(args.expected_plan)]
    if args.git_source:
        argv += ['--git-source', str(args.git_source)]
    observed = subprocess.run(argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(observed.returncode == 0, 'original offline verifier refused: '
            + observed.stderr.decode(errors='replace')[-2000:])
    result = decode(observed.stdout)
    require(result['verified'] is True and result['original_group_complete'] is True
            and result['original_group_passed'] is False
            and result['whole_chain_pq_qualified'] is False, 'original verifier result scope')
    packet = load_packet(args.original_archive, args.original_receipt, 'native', original=True)
    packet['verification'] = result
    return packet


def command_logs(packet, row, prefix):
    require(row == decode(packet['raw'][prefix + '/' + row['name'] + '.receipt.json']),
            'summary/command receipt differs: ' + row['name'])
    texts = {}
    for stream in ('stdout', 'stderr'):
        ref = row[stream]
        require(ref['name'] == row['name'] + '.' + stream + '.log', 'command stream filename')
        path = prefix + '/' + ref['name']
        require(ref == {'name': ref['name'], **member_identity(packet, path)}, 'command stream hash/mode')
        texts[stream] = packet['raw'][path].decode('utf-8')
    require(type(row['passed']) is bool and type(row['timed_out']) is bool
            and (row['exit_code'] is None or type(row['exit_code']) is int)
            and row['direct_child_reaped'] is True, 'command terminal observation shape')
    if row['timed_out']:
        require(row['passed'] is False and row['elapsed_seconds'] >= row['timeout_seconds']
                and row['exit_code'] in (-15, -9) and 'owned-group-SIGTERM' in row['cleanup'],
                'timeout must remain a failed, reaped command')
    return texts


def native_observation(text, expected):
    observations = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. (.+)$', text, re.M)
    completed = [name for name, status in observations if status == 'ok']
    require(len(completed) == len(set(completed)) and set(completed) <= set(expected),
            'unexpected or duplicate completed native name')
    require(all(name in expected for name, _ in observations), 'unexpected observed native name')
    terminal = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                          r'(\d+) measured; (\d+) filtered out; finished in .+$', text, re.M)
    valid = (len(terminal) == 1 and terminal[0][:5] == ('ok', str(len(expected)), '0', '0', '0')
             and len(observations) == len(expected) and set(completed) == set(expected)
             and re.findall(r'^running (\d+) tests?$', text, re.M) == [str(len(expected))])
    projected = ({'passed': len(expected), 'tests': sorted(expected),
                  'filtered_out': int(terminal[0][5])} if valid else None)
    return {'valid': valid, 'projection': projected, 'completed_ok_names': completed,
            'remaining_without_ok': sorted(set(expected) - set(completed)),
            'terminal_summaries': terminal}


def check_references(packet, original):
    refs = packet['manifest']['references']
    require(packet['receipt']['references'] == refs, 'manifest/receipt references differ')
    check_file_pin(refs['original_archive'], original['archive_path'], original['receipt'])
    check_file_pin(refs['original_export_receipt'], original['receipt_path'])
    check_member_pin(refs['original_summary'], original, 'native/summary.json', labelled=True)
    return refs


def check_export_scope(packet, kind, source, summary):
    status_keys = ('complete', 'all_selected_commands_passed', 'source_unchanged',
                   'provider_unchanged', 'original_group_failed', 'aggregate_budget_qualified',
                   'remaining_subset_complete', 'whole_chain_quantum_security_qualified',
                   'production_activation')
    for document in (packet['manifest'], packet['receipt']):
        require(document['kind'] == kind and document['source'] == source, 'export kind/source')
        require(document['whole_chain_quantum_security_qualified'] is False, 'export qualification flag')
        for key in status_keys:
            require(document[key] is summary.get(key), 'export exact nullable status projection: ' + key)
    require(packet['manifest']['original_logs_modified'] is False
            and packet['manifest']['cargo_target_included'] is False
            and packet['manifest']['native_executable_included'] is False, 'export scope')
    commands = summary['commands']
    failed = [row for row in commands if row['passed'] is not True]
    partial = {}
    for row in failed:
        stdout = packet['raw'][packet['prefix'] + '/' + row['stdout']['name']].decode('utf-8')
        names = re.findall(r'^test (\S+) \.\.\. ok\r?$', stdout, re.M)
        if names:
            require(len(names) == len(set(names)), 'duplicate failed-target completion name')
            partial[row['name']] = names
    require(packet['receipt']['failed_commands'] == [row['name'] for row in failed]
            and packet['receipt']['failed_target_partial_ok'] == partial
            and packet['receipt']['native_tests_observed'] ==
            sum(row.get('native_observation', {}).get('passed', 0) for row in commands if row['passed'] is True),
            'export full-target/failed-partial counts differ from raw observations')


def verify_subset(kind, archive, receipt, original, expected):
    cfg = CONFIG[kind]
    packet = load_packet(archive, receipt, 'subset')
    raw, plan, summary = packet['raw'], packet['plan'], packet['summary']
    require(sha(raw['reproduction/desktop_validate.py']) == ORIGINAL_RUNNER_SHA
            and sha(raw['reproduction/' + cfg['runner']]) == cfg['runner_sha'], 'subset frozen runners')
    require(set(name for name in raw if name.startswith('reproduction/')) ==
            {'reproduction/desktop_validate.py', 'reproduction/' + cfg['runner']}, 'subset runner roster')
    require(plan['schema'] == cfg['stem'] + '-plan-v1'
            and summary['schema'] == cfg['stem'] + '-observations-v1', 'subset schema')
    require(plan['source'] == summary['source'] == C1
            and plan['original_group'] == summary['original_group'] == ORIGINAL, 'subset source/original scope')
    require(packet['receipt']['archive'] == cfg['output'] + '.tar.xz', 'subset original archive location')
    for name in ('source-before.json', 'source-after.json', 'provider-before.json', 'provider-after.json'):
        require(raw['subset/' + name] == original['raw']['native/' + name],
                'subset/original source or provider bytes changed: ' + name)
    require(summary['source_unchanged'] is True and summary['provider_unchanged'] is True,
            'subset source/provider group did not close unchanged')
    original_target = cfg['target']
    planned = next(row for row in expected['commands'] if row['name'] == original_target)
    ordered = sorted(planned['expected_tests'])
    done, remaining = ordered[:cfg['skip']], ordered[cfg['skip']:]
    require(len(remaining) == cfg['remaining'], 'independent remaining roster count')
    failure_name = 'native/' + original_target + '.receipt.json'
    failure = decode(original['raw'][failure_name])
    require(failure['timed_out'] is True and failure['exit_code'] == -15
            and failure['timeout_seconds'] == 1200 and failure['passed'] is False
            and failure['cleanup'] == ['owned-group-SIGTERM'], 'original timeout reclassified')
    old_stdout_name = 'native/' + original_target + '.stdout.log'
    old_done = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ok$',
                          original['raw'][old_stdout_name].decode('utf-8'), re.M)
    require(old_done == done, 'original partial names do not match independently fixed skip set')
    refs = check_references(packet, original)
    check_member_pin(refs['original_failure_receipt'], original, failure_name, labelled=True)
    check_member_pin(refs['original_failure_stdout'], original, old_stdout_name, labelled=True)
    check_member_pin(refs['original_failure_stderr'], original,
                     'native/' + original_target + '.stderr.log', labelled=True)
    check_member_pin(plan['original_summary'], original, 'native/summary.json')
    check_member_pin(plan['original_failure_receipt'], original, failure_name)
    check_member_pin(plan['runner'], packet, 'reproduction/' + cfg['runner'])
    skip = [arg for name in done for arg in ('--skip', name)]
    list_argv = [cfg['exe'], *skip, '--list']
    test_argv = [cfg['exe'], *skip, '--show-output', '--test-threads=1']
    require(plan['list_argv'] == list_argv and plan['test_argv'] == test_argv
            and plan['timeout_seconds'] == 1200 and plan['concurrency'] == plan['test_threads'] == 1
            and plan['cargo_invoked_for_tests'] is False, 'subset argv/budget/thread scope')
    require(plan['completed_cases_not_repeated'] == summary['completed_original_cases_not_repeated'] == done
            and plan['remaining_cases'] == summary['requested_remaining_cases'] == remaining,
            'subset declared roster differs from fixed C1 roster')
    for document in (plan, summary):
        require(document['original_group_failed'] is True and document['aggregate_budget_qualified'] is False
                and document['whole_chain_quantum_security_qualified'] is False, 'original aggregate upgraded')
    require(summary['production_activation'] is False, 'subset activation flag')
    exe = plan['executable']
    require(exe['path'] == cfg['exe'] and exe['sha256'] == cfg['exe_sha'] and exe['bytes'] == cfg['exe_bytes']
            and type(exe['mode']) is int and exe['mode'] & 0o111, 'fixed executable observation')
    environment = plan['environment']
    original_env = original['plan']['environment']
    require(set(environment) == set(original_env) | {'TMPDIR'}
            and {k: environment[k] for k in original_env} == original_env, 'subset environment differs')
    commands = summary['commands']
    require([row['name'] for row in commands] == ['preflight', 'list-remaining', 'run-remaining'][:len(commands)]
            and len(commands) <= 3, 'subset command sequence')
    observed_run = None
    for index, row in enumerate(commands):
        name = row['name']
        require(row['cwd'] == REPO and row['source_before'] == row['source_after'] == IDENTITY,
                'subset command exact-source identity')
        texts = command_logs(packet, row, 'subset')
        base_pass = row['exit_code'] == 0 and not row['timed_out'] and row['exception'] is None
        if index == 0:
            require(row['schema'] == 'trnm-desktop-command-v1' and row['argv'] == ['bash', 'scripts/project-preflight.sh']
                    and row['timeout_seconds'] == 120 and row['expected_tests'] is None
                    and row['environment'] == original_env and row['passed'] is base_pass,
                    'subset preflight observation')
            continue
        require(commands[index - 1]['passed'] is True, 'subset ran beyond refused prerequisite')
        require(row['schema'] == cfg['stem'] + '-command-v1' and row['environment'] == environment
                and row['timeout_seconds'] == 1200 and row['argv'] == (list_argv if index == 1 else test_argv)
                and row['original_group_failed'] is True and row['aggregate_budget_qualified'] is False,
                'subset native command contract')
        binding = row['native_executable']
        require(binding['path'] == cfg['exe'] and binding['bytes'] == cfg['exe_bytes']
                and binding['sha256'] == cfg['exe_sha']
                and type(binding['device']) is int and binding['device'] >= 0
                and type(binding['inode']) is int and binding['inode'] > 0
                and re.fullmatch(r'/proc/self/fd/[0-9]+', binding['actual_exec'])
                and binding['binding'] == 'hashed descriptor held through exec; argv[0] is the original path',
                'retained descriptor binding observation')
        require(row['executable_after'] == {k: exe[k] for k in ('bytes', 'sha256', 'mode')},
                'executable after-command observation differs')
        if index == 1:
            names = re.findall(r'^([A-Za-z0-9_:]+): test$', texts['stdout'], re.M)
            valid = (row['exit_code'] == 0 and len(names) == len(remaining) and set(names) == set(remaining)
                     and re.findall(r'^(\d+) tests?, (\d+) benchmarks?$', texts['stdout'], re.M)
                     == [(str(len(remaining)), '0')])
            if valid:
                require(row.get('listed_tests') == names, 'list receipt/raw names')
            else:
                require('listed_tests' not in row and 'observation_error' in row, 'failed listing promoted')
            require(row['passed'] is (base_pass and valid and 'observation_error' not in row), 'list pass projection')
        else:
            observed_run = native_observation(texts['stdout'], remaining)
            valid = row['exit_code'] == 0 and observed_run['valid']
            if valid:
                require(row.get('native_observation') == observed_run['projection'], 'native receipt/raw result')
            else:
                require('native_observation' not in row and 'observation_error' in row, 'failed subset promoted')
            filtered = valid and observed_run['projection']['filtered_out'] == len(done)
            if valid and not filtered:
                require('observation_error' in row, 'filtered-out mismatch lacks original refusal')
            require(row['passed'] is (base_pass and filtered and 'observation_error' not in row), 'subset pass projection')
            observed_run.update(target_passed=row['passed'], timed_out=row['timed_out'],
                                exit_code=row['exit_code'], timeout_seconds=row['timeout_seconds'])
    complete = len(commands) == 3 and all(row['passed'] for row in commands) and summary['fatal'] is None
    require(summary['remaining_subset_complete'] is complete, 'subset complete projection')
    if len(commands) < 3:
        require(summary['fatal'] is not None, 'short subset lacks recorded stop reason')
    check_export_scope(packet, kind, C1, summary)
    result = {'schema': 'TRNM-C1-SUBSET-EVIDENCE-VERIFICATION1', 'verified': True, 'kind': kind, 'source': IDENTITY,
              'archive_sha256': packet['receipt']['sha256'], 'original_archive_sha256': original['receipt']['sha256'],
              'original_group_passed': False, 'original_timeout_seconds': 1200,
              'original_completed_names_not_repeated': done, 'planned_remaining_names': remaining,
              'commands_recorded': len(commands), 'remaining_subset_complete': complete,
              'failed_commands': [row['name'] for row in commands if not row['passed']],
              'not_started': ['preflight', 'list-remaining', 'run-remaining'][len(commands):],
              'native_observation': observed_run, 'partial_ok_is_not_a_target_pass': True,
              'aggregate_budget_qualified': False, 'whole_chain_pq_qualified': False, 'production_activation': False,
              'elf_bytes_rehashed': False, 'host_or_execution_attestation_claimed': False,
              'workloads_rerun': False}
    packet['verification'] = result
    return packet


def original_arguments(parser):
    parser.add_argument('--original-archive', type=Path, required=True)
    parser.add_argument('--original-receipt', type=Path, required=True)
    parser.add_argument('--original-verifier', type=Path, default=Path(__file__).with_name('verify_desktop_native.py'))
    parser.add_argument('--expected-plan', type=Path, default=Path(__file__).with_name('expected-native-plan-c09dbbe992.json'))
    parser.add_argument('--git-source', type=Path)


def write_result(result, output):
    data = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if output:
        with Path(output).open('x') as stream:
            stream.write(data)
    print(data, end='')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=tuple(CONFIG), required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    original_arguments(parser)
    args = parser.parse_args()
    expected = load_expected(args.expected_plan)
    original = verify_original(args)
    packet = verify_subset(args.kind, args.archive, args.receipt, original, expected)
    write_result(packet['verification'], args.output)


if __name__ == '__main__':
    main()
