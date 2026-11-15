#!/usr/bin/env python3
"""Read retained required-gate evidence; never execute its tests or harness."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

C1 = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
TREE = 'f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6'
SOURCE = {'commit': C1, 'tree': TREE}
SNAPSHOT_SHA256 = '81966162e2ae881348ae09cb94879b8b705fd309fba1d79b1d30aeb86f676b1f'
ORIGINAL = 'python-required-supplement-c09dbbe992'
HARNESS = 'validate_required_supplement.py'
SUITES = (('test_pq_chain_claim_guard', 55), ('test_ci_execution', 77))
EXECUTION_CLASSES = {
    '__main__.ObservationTests': 8,
    '__main__.RequiredNativeTestTests': 9,
    '__main__.SourceIdentityTests': 1,
    'test_ci_observation_process.ObserverProcessOwnershipTests': 7,
    'test_ci_source_integrity.TrackedSourceTests': 43,
    'test_rust_baseline_shards.RustShardTests': 9,
}
RAW_NAMES = {HARNESS, *(ORIGINAL + '/' + name for name in
             ('source-before.json', 'source-after.json', 'summary.json')),
             *(ORIGINAL + '/' + name + suffix for name, _ in SUITES
               for suffix in ('.receipt.json', '.stdout.log', '.stderr.log'))}
PACKAGE_FILES = {
    'REQUIRED_GATES.md', 'required-gates-raw-c09dbbe992.tar.xz',
    'required-gates-raw-index.json', 'required-gates-source-verification.json',
    'required-gates-summary.json', 'verify_required_gates.py',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('nonfinite JSON number: ' + value)

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def evaluate(raw):
    require(set(raw) == RAW_NAMES, 'unexpected or missing original files')
    before = raw[ORIGINAL + '/source-before.json']
    after = raw[ORIGINAL + '/source-after.json']
    require(before == after and sha(before) == SNAPSHOT_SHA256,
            'retained materialized snapshots differ from each other or C1')
    snapshot = decode(before)
    require({key: snapshot[key] for key in SOURCE} == SOURCE
            and snapshot['scope'] == 'all-materialized-tracked-bytes-compared-to-git'
            and snapshot['full_checkout_materialized'] is False, 'snapshot source or scope')
    present = [row['path'] for row in snapshot['files']]
    absent = snapshot['unmaterialized_sparse_paths']
    require(len(present) == len(set(present)) == 5135
            and len(absent) == len(set(absent)) == 22777
            and not set(present).intersection(absent)
            and sum(row['bytes'] for row in snapshot['files']) == 171498180,
            'materialized/sparse snapshot partition')
    constants = {}
    for node in ast.parse(raw[HARNESS]).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {'COMMIT', 'SUITES', 'CHECKS', 'STEPS'}:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
    require(constants == {'COMMIT': C1, 'SUITES': ['scripts/ci/' + name + '.py' for name, _ in SUITES],
                          'CHECKS': [], 'STEPS': []}, 'original harness command roster changed')
    receipts, observations = [], []
    for name, count in SUITES:
        receipt = decode(raw[ORIGINAL + '/' + name + '.receipt.json'])
        require(receipt['name'] == name and receipt['argv'] == ['python3', '-B', 'scripts/ci/' + name + '.py'],
                'suite command mismatch: ' + name)
        require(type(receipt['exit_code']) is int and receipt['exit_code'] == 0
                and receipt['passed'] is True and receipt['timed_out'] is False
                and type(receipt['outer_tests']) is int and receipt['outer_tests'] == count
                and receipt['timeout_seconds'] == 900, 'suite exit/count/timeout: ' + name)
        require(receipt['source_before'] == receipt['source_after'] == SOURCE,
                'suite source identity: ' + name)
        for stream in ('stdout', 'stderr'):
            ref = receipt[stream]
            require(ref['name'] == name + '.' + stream + '.log', 'log locator: ' + name)
            data = raw[ORIGINAL + '/' + ref['name']]
            require(type(ref['bytes']) is int and len(data) == ref['bytes'] and sha(data) == ref['sha256'],
                    'log bytes/hash mismatch: ' + ref['name'])
        text = raw[ORIGINAL + '/' + name + '.stderr.log'].decode('utf-8')
        ending = re.search(r'\n-{70}\nRan (\d+) tests in [0-9.]+s\n\nOK\n*\Z', text)
        require(ending is not None and int(ending[1]) == count, 'missing clean unittest completion: ' + name)
        prefix = text[:ending.start()].strip()
        ids = None
        classes = None
        if name == 'test_pq_chain_claim_guard':
            require(prefix == '.' * count, 'claim guard must have exactly 55 success dots')
            require(raw[ORIGINAL + '/' + name + '.stdout.log'] == b'', 'claim guard stdout changed')
        else:
            lines = prefix.splitlines()
            matches = [re.fullmatch(r'(test_\w+) \(([^)]+)\) \.\.\. ok', line) for line in lines]
            require(len(matches) == count and all(matches), 'missing, skipped or failed verbose result')
            require(all(match[2].endswith('.' + match[1]) for match in matches), 'verbose method identity')
            ids = [match[2] for match in matches]
            require(len(set(ids)) == count, 'duplicate verbose success ID')
            classes = dict(Counter(ident.rsplit('.', 1)[0] for ident in ids))
            require(classes == EXECUTION_CLASSES, 'source/observer/retained class roster mismatch')
            # These are deliberately failed fixture receipts, not failed outer tests.
            output = raw[ORIGINAL + '/' + name + '.stdout.log'].decode('utf-8').splitlines()
            fixture_rows = [decode(line) for line in output]
            require([row.get('result') for row in fixture_rows] == ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'PASS', 'FAIL'],
                    'retained nested fixture outcomes changed')
            require(all(set(row) == {'receipt', 'result'} for row in fixture_rows), 'nested fixture output shape')
        receipts.append(receipt)
        observations.append({'name': name, 'argv': receipt['argv'], 'actual_top_level_tests': count,
                             'exit_code': 0, 'timed_out': False, 'skipped_tests': 0,
                             'completion_format': 'success-dots' if ids is None else 'unique-verbose-success-ids',
                             'named_success_ids': ids, 'named_success_class_counts': classes,
                             'elapsed_seconds': receipt['elapsed_seconds'],
                             'stdout': receipt['stdout'], 'stderr': receipt['stderr']})
    summary = decode(raw[ORIGINAL + '/summary.json'])
    require(summary['source'] == SOURCE and summary['commands'] == receipts
            and summary['source_unchanged'] is True and summary['all_selected_commands_passed'] is True
            and summary['status'] == 'HOLD_NO_GO', 'original required-gate summary mismatch')
    require(all(summary[field] is False for field in
                ('hosted_ci_observed', 'production_activation', 'whole_chain_pq_qualified')),
            'original qualification flags changed')
    return {'source': SOURCE, 'completed_commands': 2, 'top_level_python_executions': 132,
            'suites': observations, 'source_before_after_bytes_equal': True,
            'retained_snapshot_sha256': SNAPSHOT_SHA256, 'full_checkout_materialized': False,
            'materialized_files': 5135, 'materialized_bytes': 171498180,
            'unmaterialized_sparse_paths': 22777, 'skipped_tests': 0,
            'nested_fixture_outcomes_are_not_outer_test_failures': True,
            'native_workloads_rerun_by_verifier': False, 'tests_rerun_by_verifier': False,
            'hosted_ci_observed': False, 'whole_chain_pq_qualified': False, 'production_activation': False}


def verify_git_source(repo, snapshot):
    """Check the retained manifest against local C1 objects, never fetch or run tests."""
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull)
    command = ['git', '--no-replace-objects', '-c', 'core.fsmonitor=false', '-C', str(repo)]

    def git(*args):
        return subprocess.check_output(command + list(args), env=env)

    require(git('rev-parse', C1 + '^{tree}').decode().strip() == TREE, 'C1 Git tree differs')
    entries = {}
    for entry in git('ls-tree', '-rlz', '--full-tree', C1).split(b'\0'):
        if not entry:
            continue
        metadata, path = entry.split(b'\t', 1)
        mode, kind, oid, size = metadata.split()
        require(kind == b'blob', 'non-blob source entry')
        entries[path.decode()] = (mode.decode(), oid.decode(), int(size))
    present = {row['path']: row for row in snapshot['files']}
    absent = set(snapshot['unmaterialized_sparse_paths'])
    require(set(entries) == set(present) | absent and not set(present) & absent,
            'retained partition does not cover the C1 tree')
    with subprocess.Popen(command + ['cat-file', '--batch'], env=env,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as reader:
        for path, row in present.items():
            require(entries[path] == (row['mode'], row['git_blob'], row['bytes']), 'Git entry mismatch: ' + path)
            oid = row['git_blob'].encode()
            reader.stdin.write(oid + b'\n')
            reader.stdin.flush()
            require(reader.stdout.readline().split() == [oid, b'blob', str(row['bytes']).encode()],
                    'missing/wrong local Git blob: ' + path)
            data = reader.stdout.read(row['bytes'])
            require(len(data) == row['bytes'] and reader.stdout.read(1) == b'\n'
                    and sha(data) == row['sha256'], 'Git blob content mismatch: ' + path)
        reader.stdin.close()
        require(reader.wait(timeout=30) == 0, 'Git object reader did not finish')
    return {'source': SOURCE, 'materialized_blob_records_verified': len(present),
            'unmaterialized_tree_entries': len(absent), 'git_object_bytes_verified': 171498180,
            'current_checkout_not_relabelled_as_original_execution': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--originals', type=Path, help='compare archived bytes to original workspace files')
    parser.add_argument('--git-source', type=Path, help='also verify retained source records against local C1 Git objects')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    listed = set()
    for line in (base / 'REQUIRED_GATES_SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        require(name in PACKAGE_FILES and name not in listed, 'unsafe/duplicate checksum name')
        require(sha((base / name).read_bytes()) == digest, 'package checksum mismatch: ' + name)
        listed.add(name)
    require(listed == PACKAGE_FILES, 'incomplete supplement checksum inventory')
    index = decode((base / 'required-gates-raw-index.json').read_bytes())
    archive_path = base / 'required-gates-raw-c09dbbe992.tar.xz'
    require(index['archive']['path'] == archive_path.name
            and archive_path.stat().st_size == index['archive']['bytes']
            and sha(archive_path.read_bytes()) == index['archive']['sha256'], 'archive identity mismatch')
    raw = {}
    with tarfile.open(archive_path, 'r:xz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts
                    and member.name in RAW_NAMES and member.name not in raw
                    and 0 <= member.size <= 8 * 1024 * 1024, 'unsafe/duplicate/non-file archive member')
            raw[member.name] = archive.extractfile(member).read()
    rows = {row['path']: row for row in index['files']}
    require(len(rows) == len(index['files']) and set(rows) == set(raw) == RAW_NAMES,
            'raw archive inventory mismatch')
    for path, data in raw.items():
        require(len(data) == rows[path]['bytes'] and sha(data) == rows[path]['sha256'], 'raw member mismatch: ' + path)
        if args.originals is not None:
            require((args.originals / path).read_bytes() == data, 'original bytes changed: ' + path)
    require(index['file_count'] == len(raw) == 10
            and index['total_original_bytes'] == sum(map(len, raw.values())), 'raw inventory totals')
    actual = evaluate(raw)
    summary = decode((base / 'required-gates-summary.json').read_bytes())
    require(summary['verified_observations'] == actual, 'derived supplement summary mismatch')
    source_check = decode((base / 'required-gates-source-verification.json').read_bytes())
    require(source_check['source'] == SOURCE and source_check['retained_snapshot_sha256'] == SNAPSHOT_SHA256,
            'independent source observation identity')
    require(sorted(actual['suites'][1]['named_success_ids']) == source_check['expected_ci_execution_success_ids'],
            'verbose successes do not match the independently inspected C1 source roster')
    preserved = source_check['preserved_original_static_files']
    require(len(preserved) == 8, 'original static file inventory')
    for name, ref in preserved.items():
        require('/' not in name and name not in {'', '.', '..'}, 'unsafe original static path')
        data = (base / name).read_bytes()
        require(len(data) == ref['bytes'] and sha(data) == ref['sha256'], 'original static file changed: ' + name)
    old = decode((base / 'static-summary.json').read_bytes())['verified_observations']
    require(old['source'] == SOURCE and old['top_level_python_controls'] == 577
            and old['initial_integration_terminal_state'] == 'unknown_no_receipt'
            and old['initial_progress_dots_excluded'] == 18 and old['same_uninterrupted_run_claimed'] is False,
            'original static count/unknown observation changed')
    require(summary['combined_execution_accounting'] == {
        'prior_static_top_level_executions': 577, 'required_supplement_top_level_executions': 132,
        'combined_top_level_executions': 709, 'independent_security_property_count': None,
        'same_uninterrupted_run_claimed': False, 'initial_unknown_preserved': True},
        'combined accounting overstates its scope')
    git_result = verify_git_source(args.git_source, decode(raw[ORIGINAL + '/source-before.json'])) if args.git_source else None
    print(json.dumps({'verified': True, 'source': SOURCE, 'raw_files': len(raw),
                      'supplement_top_level_executions': 132, 'combined_top_level_executions': 709,
                      'independent_security_property_count': None, 'original_unknown_preserved': True,
                      'original_static_files_unchanged': 8, 'originals_compared': args.originals is not None,
                      'git_source_verification': git_result, 'tests_executed': False,
                      'native_workloads_executed': False, 'full_checkout_materialized': False}, sort_keys=True))


if __name__ == '__main__':
    main()
