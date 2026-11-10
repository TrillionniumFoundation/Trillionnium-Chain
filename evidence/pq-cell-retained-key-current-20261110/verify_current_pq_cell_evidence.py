#!/usr/bin/env python3
"""Read retained originals and command receipts without promoting qualification."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

SOURCE = 'a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667'
TREE = 'b621fde199f0e52a8410f765fbda0d633a32d5ff'
EVIDENCE = 'evidence/pq-cell-retained-key-current-20261110'
MAX_BYTES = 128 * 1024 * 1024
SOURCE_COMMANDS = {
    'ci-contract', 'ci-execution', 'claim-controls', 'claim-inspector',
    'custody-v2-inspector', 'custody-v2', 'inventory', 'lifetime-inspector',
    'lifetime-tests', 'phase-reader', 'pq-corpus', 'pq-source-controls',
    'repository', 'source-controls',
}
NATIVE_COMMANDS = {
    'da-complete', 'format', 'graph-offline', 'npq-cli', 'pipeline-build',
    'signed-sealed-pipeline', 'strict-clippy',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def regular(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'not a regular file: ' + str(path))
    require(before.st_size <= MAX_BYTES, 'oversize file: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(raw) == before.st_size, 'file changed during read: ' + str(path))
    return raw


def relative(root, name):
    require(isinstance(name, str) and name, 'invalid relative path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'noncanonical relative path')
    result = root.joinpath(*path.parts)
    require(result.resolve().is_relative_to(root.resolve()), 'relative path escapes root')
    for parent in result.parents:
        if parent == root:
            break
        require(not parent.is_symlink(), 'symlinked parent')
    return result


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def changed_paths(root):
    # Include committed descendants, staged/unstaged changes and each untracked
    # file; do not interpret a directory-only status as complete file coverage.
    paths = {item.decode() for item in git(root, 'diff', '--name-only', '-z', SOURCE).split(b'\0') if item}
    status = git(root, 'status', '--porcelain', '-z', '--untracked-files=all').split(b'\0')
    index = 0
    while index < len(status):
        record = status[index]
        index += 1
        if not record:
            continue
        require(len(record) >= 4 and record[2:3] == b' ', 'unexpected porcelain status')
        paths.add(record[3:].decode())
        if b'R' in record[:2] or b'C' in record[:2]:
            require(index < len(status) and status[index], 'missing rename source')
            paths.add(status[index].decode())
            index += 1
    require(all(path.startswith(EVIDENCE + '/') for path in paths),
            'a changed/new path lies outside the current evidence directory')
    return sorted(paths)


def verify(root, compare_originals):
    head = git(root, 'rev-parse', 'HEAD').decode().strip()
    evidence = relative(root, EVIDENCE)
    mapping_raw = regular(evidence / 'retained-originals.json')
    mapping = parse(mapping_raw)
    require(isinstance(mapping, list) and len(mapping) == 123, 'expected exactly 123 retained originals')
    decoded = {}
    original_paths = set()
    gzip_count = 0
    compared = 0
    for item in mapping:
        require(set(item) == {'gzip', 'original_bytes', 'original_path', 'original_sha256', 'path'},
                'unexpected retained-original mapping fields')
        name = item['path']
        require(name not in decoded, 'duplicate retained destination')
        require(item['original_path'] not in original_paths, 'duplicate retained original')
        original_paths.add(item['original_path'])
        require(type(item['gzip']) is bool and type(item['original_bytes']) is int
                and 0 <= item['original_bytes'] <= MAX_BYTES, 'invalid retained size/compression')
        require(re.fullmatch('[0-9a-f]{64}', item['original_sha256']) is not None,
                'invalid original digest')
        retained = regular(relative(evidence, name))
        if item['gzip']:
            with gzip.GzipFile(fileobj=io.BytesIO(retained)) as stream:
                raw = stream.read(item['original_bytes'] + 1)
            gzip_count += 1
        else:
            raw = retained
        require(len(raw) == item['original_bytes'] and sha(raw) == item['original_sha256'],
                'retained original size/hash mismatch: ' + name)
        if compare_originals:
            original = Path(item['original_path'])
            require(original.is_absolute() and original.resolve().is_relative_to(root.parent.resolve()),
                    'original path is outside this task workspace')
            require(regular(original) == raw, 'retained bytes differ from available original: ' + name)
            compared += 1
        decoded[name] = raw

    source_prefix = 'source-validation/'
    native_prefix = 'selected/current-native-validation/'
    source_receipt_file_count = sum(name.startswith(source_prefix) for name in decoded)
    native_selection_count = sum(name.startswith('selected/') for name in decoded)
    source_count = len(decoded) - native_selection_count
    require(source_count == 61 and source_receipt_file_count == 57 and native_selection_count == 62,
            'source/native retention selections changed')
    command_groups = []
    for scope, prefix, expected in [('source-controls', source_prefix, SOURCE_COMMANDS),
                                     ('native-and-toolchain', native_prefix, NATIVE_COMMANDS)]:
        receipts = {}
        for name, raw in decoded.items():
            if name.startswith(prefix) and name.endswith('.json'):
                data = parse(raw)
                if isinstance(data, dict) and data.get('schema') == 'trnm-pq-native-command-v1':
                    receipts[PurePosixPath(name).stem] = data
        require(set(receipts) == expected, 'command receipt roster differs: ' + scope)
        records = []
        for label, receipt in sorted(receipts.items()):
            require(receipt['status'] == 'command_succeeded'
                    and type(receipt['exit_code']) is int and receipt['exit_code'] == 0,
                    'unconfirmed command result: ' + label)
            source = receipt['before']
            require(receipt['after'] == source, 'command source endpoints differ: ' + label)
            require(source['kind'] == 'head' and source['candidate'] == SOURCE
                    and source['tested_commit'] == SOURCE and source['tested_tree'] == TREE
                    and source['tracked_worktree_verified'] is True
                    and source['tracked_entries'] == 27855 and source['tracked_bytes'] == 2528691640,
                    'command source identity differs: ' + label)
            require(source['base'] is None and source['prospective_merge'] is None,
                    'unexpected command merge context')
            log_name = receipt['log_file']
            require(isinstance(log_name, str) and PurePosixPath(log_name).name == log_name,
                    'unsafe command log basename')
            paths = [prefix + log_name, prefix + log_name + '.gz']
            available = [path for path in paths if path in decoded]
            require(len(available) == 1, 'missing/ambiguous retained command log: ' + label)
            log = decoded[available[0]]
            require(len(log) == receipt['log_bytes'] and sha(log) == receipt['log_sha256'],
                    'command log disagrees with receipt: ' + label)
            records.append({'label': label, 'status': receipt['status'], 'exit_code': 0,
                            'source': SOURCE, 'tree': TREE, 'source_endpoints_equal': True,
                            'log_bytes': len(log), 'log_sha256': sha(log)})
        command_groups.append({'scope': scope, 'commands': records, 'command_count': len(records)})

    native = lambda name: parse(decoded[native_prefix + name])
    execution = native('signed-sealed-pipeline.json')['native_execution']
    pin = native('pipeline-binary.json')
    post = native('pipeline-artifact-path-observations.json')
    review = native('pipeline-independent-verification.json')
    require(execution['status'] == 'PINNED_AND_OBSERVED' and execution['native_exit_code'] == 0
            and execution['child_reaped'] is True, 'pipeline native dispatch was not confirmed')
    expected_hash = pin['sha256']
    require(pin['source'] == SOURCE and execution['expected_sha256'] == expected_hash
            and execution['dispatch_object']['sha256'] == expected_hash
            and execution['dispatch_object_after_sha256'] == expected_hash
            and execution['observation']['status'] == 'OBSERVED'
            and execution['observation']['sha256'] == expected_hash,
            'pipeline dispatch/post-dispatch/live process pins disagree')
    original_identity = tuple(execution['dispatch_object'][key] for key in ('device', 'inode', 'bytes'))
    require(tuple(execution['observation'][key] for key in ('device', 'inode', 'bytes'))
            == original_identity, 'pipeline observed executable object differs')
    require(post['source'] == SOURCE and post['original_pin'] == expected_hash,
            'later artifact observations have wrong source/pin')
    plain = [row for row in post['observations'] if row['path'] == pin['path']]
    retained_objects = [row for row in post['observations'] if row['matches_original_pin'] is True
                        and row['matches_original_file_object'] is True]
    require(len(plain) == 1 and plain[0]['sha256'] != expected_hash
            and plain[0]['matches_original_pin'] is False
            and plain[0]['matches_original_file_object'] is False,
            'later plain-path replacement observation differs')
    require(len(retained_objects) == 1 and retained_objects[0]['sha256'] == expected_hash
            and retained_objects[0]['path'] != pin['path']
            and tuple(retained_objects[0][key] for key in ('device', 'inode', 'bytes')) == original_identity,
            'hashed original artifact observation differs')
    if compare_originals:
        for row in post['observations']:
            path = Path(row['path'])
            require(path.is_absolute() and path.resolve().is_relative_to(root.parent.resolve()),
                    'artifact observation path escapes this task workspace')
            meta = path.lstat()
            raw = regular(path)
            require((meta.st_dev, meta.st_ino, len(raw), sha(raw))
                    == (row['device'], row['inode'], row['bytes'], row['sha256']),
                    'current artifact differs from the later recorded observation')
    require(review['result'] == 'PASS' and review['source'] == SOURCE and review['tree'] == TREE
            and review['executable_sha256'] == expected_hash
            and review['recorded_dispatch_and_observed_process_hashes_match'] is True
            and review['current_binary_fingerprint_verified'] is False
            and review['post_execution_path_observation']['status'] == 'REPLACED_SINCE_RECORDED_EXECUTION',
            'pipeline scope interpretation differs')
    failure = native('pipeline-verifier-postcheck-failure.json')
    require(failure['source'] == SOURCE and failure['exit_code'] == 1
            and failure['not_a_native_execution_rerun'] is True
            and failure['expected_recorded_binary']['sha256'] == expected_hash
            and failure['current_path_observation']['sha256'] == plain[0]['sha256'],
            'original postcheck verifier failure was not preserved')
    pipeline = parse(decoded[native_prefix + 'signed-sealed-pipeline.log.gz'])
    require(pipeline['status'] == 'PASS_COMPONENT_PIPELINE' and pipeline['stage'] == 'complete'
            and pipeline['hepta_started'] is False and pipeline['final_use_granted'] is False,
            'pipeline component result/scope differs')

    paths = changed_paths(root)
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == head,
            'Git HEAD moved during evidence verification')
    return {
        'schema': 'trnm-current-cell-evidence-independent-byte-review-v1',
        'result': 'PASS', 'verified_utc': datetime.now(timezone.utc).isoformat(),
        'reviewed_checkout_head': head, 'actual_executed_source': SOURCE, 'actual_executed_tree': TREE,
        'retained_originals_mapping_sha256': sha(mapping_raw),
        'retained_originals_verified': len(decoded), 'gzip_originals_verified': gzip_count,
        'original_files_compared': compared, 'compare_available_originals': compare_originals,
        'retention_scopes': {'source_validation_and_setup_files': source_count,
                             'source_validation_receipt_log_files': source_receipt_file_count,
                             'explicit_native_selection_files': native_selection_count},
        'command_scopes': command_groups, 'command_receipts_verified': 21,
        'test_counts_across_commands_or_harnesses_summed': False,
        'whole_workspace_test_total': None,
        'pipeline': {'native_command_exit': 0, 'native_process_status': execution['status'],
                     'original_pinned_sha256': expected_hash,
                     'dispatch_after_and_live_process_pins_agree': True,
                     'later_plain_path_replaced': True,
                     'later_plain_path_sha256': plain[0]['sha256'],
                     'hashed_original_path_preserves_original_file_object': True,
                     'later_observation_files_rechecked': compare_originals,
                     'postcheck_verifier_failure_retained': True,
                     'postcheck_verifier_failure_is_native_pipeline_failure': False,
                     'component_result': pipeline['status'], 'synthetic_fixture': True},
        'all_new_or_changed_paths_within_current_evidence_folder': True,
        'new_or_changed_path_count': len(paths),
        'scope': 'retained-byte integrity and command/source relationship checks only',
        'independent_execution_authentication': False,
        'complete_lifetime_executable_image_verified': False,
        'cell_performance_improvement_measured': False,
        'real_model_efficacy_assessed': False,
        'actual_lifetime_failure_bound': None, 'composition_coverage_proved': False,
        'whole_chain_pq_qualified': False, 'production_activation': False,
        'qualification': 'HOLD_NO_GO',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recorded-only', action='store_true',
                        help='explicitly omit comparisons with available original task files/artifacts')
    args = parser.parse_args()
    root = args.root.resolve()
    require(args.output.is_absolute() and not args.output.resolve().is_relative_to(root),
            'report must be outside source')
    try:
        report = verify(root, not args.recorded_only)
        code = 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, gzip.BadGzipFile) as error:
        report = {'schema': 'trnm-current-cell-evidence-independent-byte-review-v1',
                  'result': 'FAIL', 'reason': str(error),
                  'whole_chain_pq_qualified': False, 'production_activation': False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'result': report['result'], 'report': str(args.output),
                      'reason': report.get('reason')}, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
