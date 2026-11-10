#!/usr/bin/env python3
"""Retain failed C2/C3 and independently validated M1 in an evidence-only E1.

This independent recorder never executes the old v2 publisher's completion
path. It loads only pinned read-only helpers, requires actual M1 observations,
and permits a normal evidence commit followed by an explicit fast-forward
push and a REST draft pull request. Unknown remote writes are read back only.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
import types

BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
C3 = 'a715b2c8e89732ce356ebae67f978ef232156c04'
C3_TREE = 'cc44e4c526d9b52d04697169a9b1d3eeb5079451'
UPSTREAM = 'df927b6ffaecff293b9e9428e3ba516f47cd101a'
M1 = '8ab052065ae8307b1ab2c9d42b0dca229a5a3b9d'
M1_TREE = '218f49c3a4b1495f90c0d885433c0ec9ad51fb3c'
PREFIX = 'evidence/pon-followthrough-20261110-685a/final-integration'
VERIFY = 'scripts/ci/verify_ci_source.py'
BRANCH = 'fix/chain-pon-followthrough-20261110-685a'
REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
ACCOUNT = 'ProfHepta'
PR_BASE = 'fix/chain-hepta-closure-candidate-20261109-481716'
MARKER = '<!-- pon-followthrough-20261110-685a -->'
TITLE = 'fix(pon): retain readback fixes, quorum merge and failed native observations'
COMMIT_MESSAGE = 'docs(pon): retain merged checks and original failed observations'
PRIOR_PUBLISHER_SHA = 'abc4cb69b7d55b9a2bee93b4da19a8992d7389b59a3e5df2898ff1ed10df753e'
VALIDATOR_SHA = '825fd284f1a995b3c66753d9338b6ea794afcb5b0c759b701a3831eb63b1ed84'
MERGE_RECORDER_SHA = '67524dc55ebc052d38135324af9455ab3c06ed072294ae6a11167226ced48580'
MERGE_ARCHIVE_SHA = 'da285a18285c8f4a14204c75e3a8b1795a2dcd3bdc3635af127b1e9bfe9ccbf0'
MERGE_MANIFEST_SHA = 'b9b8f43a3df20dbb88257594e4efe40a7edfb3bf2d316259535aaff571e296d3'
MERGE_SUMMARY_SHA = '34d1553565881c298c47c5c3576b4757d8701a43f99e629cab72ebdd1c7b6b26'
MERGED_SOURCE_SHA = '410f65105cfcfe45438e228fe44b11c7eaabb9a1b2d1f93d03bfdb3cca4198c0'
MERGE_CORPUS_SHA = 'd89c64a34772de4c6aa33d7ec5361e472aa05e635ca970cf34e501398b7f3453'
HYDRATE_RECORDER_SHA = 'a6256557384ebaefaffd61dd7e3089b948115e2df9287bc50b1c3967c67cd135'
HYDRATE_SUMMARY_SHA = 'b966c60b37778cf6dbb1b9dc1ec1f5f9c0457adece5ba9a19f6ac03468886174'
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_MEMBERS = 8192
P = V = None


class Refusal(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def load_pinned_module(path, name, expected):
    require(path.is_absolute() and path == path.resolve(), 'pinned helper path is aliased')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, 'pinned helper is not regular')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_FILE + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and len(raw) == before.st_size, 'pinned helper changed during read')
    finally:
        os.close(fd)
    require(hashlib.sha256(raw).hexdigest() == expected, 'pinned helper bytes differ: ' + path.name)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def initialize_dependencies(prior, validator):
    global P, V
    P = load_pinned_module(prior, 'retained_publication_v2_helpers', PRIOR_PUBLISHER_SHA)
    V = load_pinned_module(validator, 'retained_m1_validator_helpers', VALIDATOR_SHA)
    for name in ('sha', 'blob', 'encoded', 'strict_json', 'relative', 'directory', 'read_regular',
                 'properties', 'write_new', 'atomic_json', 'git', 'gtext', 'tree_entries',
                 'snapshot_identity', 'check_command_references', 'original_bracket'):
        globals()[name] = getattr(P, name)


def snapshot(root, *, nul_logs=()):
    """Preserve regular observations; allow only two named NUL-delimited Git logs."""
    directory(root)
    result, excluded, total = {}, [], 0
    for parent, folders, files in os.walk(root, followlinks=False,
                                          onerror=lambda error: (_ for _ in ()).throw(error)):
        for folder in folders:
            path = Path(parent) / folder
            require(not path.is_symlink() and folder not in ('.git', 'target', 'node_modules', '__pycache__'),
                    'unreviewed observation directory: ' + str(path))
        for file in sorted(files):
            path = Path(parent) / file
            name = relative(str(path.relative_to(root)))
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode), 'nonregular observation: ' + str(path))
            if path.suffix in ('.lock', '.index'):
                excluded.append({'path': name, 'bytes': metadata.st_size,
                                 'reason': 'temporary process lock or Git index; not copied'})
                continue
            require(path.suffix in ('.json', '.log', '.patch', '.txt', '.md', '.py', '.sh'),
                    'unreviewed observation extension: ' + str(path))
            raw, mode = read_regular(path)
            require(not raw.startswith((b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe')),
                    'executable binary is not an observation: ' + name)
            require(b'\0' not in raw or name in nul_logs, 'unreviewed NUL-containing observation: ' + name)
            if name in nul_logs:
                require(all(not row or row.startswith(b'H ') for row in raw.split(b'\0')),
                        'original NUL-delimited index log differs')
            if path.suffix == '.json':
                strict_json(raw)
            total += len(raw)
            require(total <= MAX_TOTAL and len(result) < MAX_MEMBERS, 'observation collection bound exceeded')
            result[name] = {'raw': raw, 'original_mode': oct(mode), **properties(raw)}
    return result, excluded


def json_member(files, name):
    require(name in files, 'required original observation missing: ' + name)
    return strict_json(files[name]['raw'])


def terminal_rows(files):
    rows = json_member(files, 'commands.json')
    require(type(rows) is list and rows and len({r.get('label') for r in rows}) == len(rows),
            'missing or duplicate actual command rows')
    check_command_references(files)
    for row in rows:
        require(type(row.get('exit_code')) is int and type(row.get('argv')) is list
                and all(type(item) is str for item in row['argv']), 'invalid actual command row')
        require(type(row.get('start_unix_ns')) is int and type(row.get('end_unix_ns')) is int
                and 0 < row['start_unix_ns'] <= row['end_unix_ns'], 'actual command interval missing')
    return rows


def plain_scope(value):
    require(value.get('native_full_suite_passed') is False
            and value.get('open_consensus_qualified') is False
            and value.get('production_activation') is False and value.get('security_status') == 'HOLD',
            'observation qualification was upgraded')


def validate_merged_controls(files, root, out, merge_files):
    """Recompute the exact frozen 38-command contract from original raw streams."""
    require('failure.json' not in files, 'M1 validation retained a failure and cannot be published')
    summary, source, status = (json_member(files, name) for name in ('summary.json', 'source.json', 'status.json'))
    require(summary.get('schema') == 'pon-upstream-union-observations-v1'
            and source.get('schema') == 'pon-upstream-union-source-v1'
            and summary.get('source') == M1 and summary.get('tree') == M1_TREE
            and summary.get('parents') == [C3, UPSTREAM]
            and summary.get('recorder_sha256') == source.get('recorder_sha256') == VALIDATOR_SHA,
            'M1 observation source/recorder differs')
    require(source.get('merge', {}).get('commit') == M1
            and source['merge'].get('tree') == M1_TREE and source['merge'].get('parents') == [C3, UPSTREAM],
            'M1 raw source commit differs')
    for key in ('observation_complete', 'all_required_checks_passed', 'source_bracket_identical',
                'original_evidence_blobs_and_modes_preserved'):
        require(summary.get(key) is True, 'M1 actual prerequisite is incomplete: ' + key)
    for key in ('full_node_suite_executed', 'full_node_suite_passed', 'native_full_suite_passed',
                'first_parent_test_results_reused', 'second_parent_test_results_reused',
                'original_c3_failed_observation_rewritten', 'source_mutations_performed',
                'history_fetched_or_rewritten', 'published', 'hosted_ci_observed_complete'):
        require(summary.get(key) is False, 'M1 observation scope differs: ' + key)
    plain_scope(summary)
    require(summary.get('draft_only') is True and summary.get('failure_reason') is None
            and summary.get('failed_commands') == [] and summary.get('commands') == summary.get('planned_commands') == 38,
            'M1 failures, partial commands or qualification are inconsistent')
    require(status.get('schema') == 'pon-upstream-union-status-v1'
            and status.get('stage') == 'complete-observation' and status.get('phase') == 'finished'
            and status.get('last_exit') == 0 and status.get('source') == M1,
            'M1 validator did not reach its actual terminal state')
    expected_plan = V.plan(root, out, M1)
    require(json_member(files, 'planned-checks.json') == expected_plan, 'M1 original planned command set differs')
    verifier = ['python3', '-B', VERIFY, '--kind', 'head', '--expected-head', M1, '--output']
    expected = [('preflight', ['bash', 'scripts/project-preflight.sh']),
                ('source-before', verifier + [str(out / 'source-before.json')])]
    expected += [(row['label'], row['argv']) for row in expected_plan['checks']]
    expected += [('source-after', verifier + [str(out / 'source-after.json')]),
                 ('source-identical', ['cmp', str(out / 'source-before.json'), str(out / 'source-after.json')])]
    rows = terminal_rows(files)
    require(len(rows) == 38 and [(row['label'], row['argv']) for row in rows] == expected,
            'M1 actual command names, order or arguments differ')
    named, native = {}, {}
    for row in rows:
        require(row.get('cwd') == str(root) and row['exit_code'] == row.get('process_exit_code') == 0
                and row.get('timed_out') is False and row.get('interrupted') is False
                and row.get('recorder_error') is None and 'observation_error' not in row,
                'M1 command did not actually pass: ' + row['label'])
        require(json_member(files, row['label'] + '.command.json') == row, 'M1 command sidecar differs')
        if row['label'] in V.NATIVE_LABELS:
            value = V.native_observation(row['label'], files[row['stdout']['file']]['raw'], row['exit_code'])
            require(row.get('native_observation') == value, 'M1 native reader outcome differs')
            native[row['label']] = value
        if row['label'] in ('test_w1_factorial_native_gate', 'test_w1_lifetime_ledger'):
            value = V.python_named_observation(row['label'], files[row['stderr']['file']]['raw'], row['exit_code'])
            require(row.get('python_named_observation') == value, 'M1 named Python outcome differs')
            named[row['label']] = value
    require(summary.get('native_targeted_results') == native and summary.get('python_named_results') == named,
            'M1 summary does not match actual executed named suites')
    original_bracket(files, 'source-before.json', 'source-after.json', M1, M1_TREE)
    require(files['merge-source-only-summary.json']['raw'] == merge_files['summary.json']['raw']
            and summary.get('merge_source_only_summary_sha256') == source.get('merge_source_only_summary_sha256')
            == MERGE_SUMMARY_SHA, 'M1 tests lost their actual source-only merge receipt')
    require(files['w1-lifetime-report.stdout.log']['raw']
            == git(root, 'show', M1 + ':' + V.LEDGER + '/project-report.json'),
            'M1 actual ledger report differs from its retained input report')
    return {'merged_source': M1, 'merged_tree': M1_TREE, 'actual_commands': 38,
            'all_required_checks_passed': True, 'source_bracket_identical': True,
            'native_targeted_results': native, 'python_named_results': named,
            'validator_sha256': VALIDATOR_SHA, 'summary_sha256': files['summary.json']['sha256'],
            'full_node_suite_executed': False, 'full_node_suite_passed': False,
            'native_full_suite_passed': False, 'parent_test_results_inherited': False,
            'hosted_ci_observed_complete': False, 'security_status': 'HOLD'}


def validate_failed_c3(controller, driver, root, controller_out, bundle, original, followup):
    """The failed parent stays 25 zero / 4 nonzero; no child-native execution exists."""
    require('summary.json' not in controller and 'summary.json' not in driver,
            'the failed C3 attempt gained a nonexistent completion summary')
    require(not any(name.startswith('binding-native.') for name in driver),
            'driver03 gained a native child execution after its failure')
    state = json_member(controller, 'state.json')
    require(state.get('phase') == 'validation_failed' and state.get('source_c3') == C3
            and state.get('prepared_tree') == C3_TREE and state.get('source_c2') == C2,
            'actual failed controller state differs')
    attempts = state.get('validation_runs')
    require(type(attempts) is list and len(attempts) == 1 and attempts[0].get('summary') == 'validation-01-summary.json'
            and attempts[0].get('complete') is False and attempts[0].get('state') == 'finished',
            'actual C3 validation attempt was omitted or replaced')
    summary = json_member(controller, 'validation-01-summary.json')
    require(summary.get('schema') == 'pon-followthrough-binding-child-checks-v2'
            and summary.get('binding_child_c3') == C3 and summary.get('binding_child_tree') == C3_TREE
            and summary.get('complete') is False and summary.get('source_bracket_identical') is True,
            'C3 failed summary was upgraded or lost its source bracket')
    P.failed_native_draft_scope(summary)
    original_bracket(controller, 'validation-01-source-before.json', 'validation-01-source-after.json', C3, C3_TREE)
    checks = json_member(controller, 'validation-01-planned-checks.json')
    require(checks.get('source') == C3 and checks.get('checks_already_passed') is False
            and checks.get('native_full_suites_repeated') is False, 'C3 original plan scope differs')
    labels = ['source-before', 'preflight', *[Path(path).stem for path in V.PYTHON_SUITES[:-1]],
              'corpus', 'ci-contract', 'qrom-current-named', 'qrom-historical-drift', 'qrom-current-implementation',
              'authority-register', 'pq128-lifetime', 'w1-lifetime-report', 'w1-lifetime-report-identical',
              'distributed-inventory', 'repository-and-markdown-links', 'source-diff-whitespace', 'format',
              'source-after', 'source-identical']
    require(len(labels) == 29 and [pair[0] for pair in checks.get('checks', [])] == labels[1:-2],
            'C3 original 29-command roster differs')
    all_rows = terminal_rows(controller)
    rows = [row for row in all_rows if row['label'].startswith('validation-01-')]
    require([row['label'] for row in rows] == ['validation-01-' + label for label in labels],
            'C3 raw validation rows differ')
    failed = {'test_ci_contract': 1, 'ci-contract': 1, 'repository-and-markdown-links': 2,
              'test_w1_lifetime_ledger': 1}
    require(all(row['exit_code'] == failed.get(row['label'].removeprefix('validation-01-'), 0)
                and row.get('cwd') == str(root) for row in rows), 'actual C3 failure exits were relabeled')
    require(summary.get('commands') == [{'label': row['label'], 'exit_code': row['exit_code']} for row in rows],
            'C3 summary omitted or relabeled a raw check')
    require([(row['label'].removeprefix('validation-01-'), row['argv']) for row in rows[1:-2]]
            == [(label, argv) for label, argv in checks['checks']], 'C3 raw command arguments differ from original plan')
    failure = json_member(controller, 'failure.json')
    require(failure.get('reason') == 'one or more actual C3 checks failed; no push or qualification performed'
            and failure.get('no_push_or_activation') is True and failure.get('requested_phase') == 'all'
            and failure.get('security_status') == 'HOLD', 'C3 original failure record differs')
    command = json_member(driver, 'integrate.command.json')
    require(command.get('exit_code') == 2 and command.get('cwd') == str(root)
            and command.get('argv') == ['python3', '-B', str(bundle / P.CONTROLLER_PATH), '--phase', 'all',
                '--root', str(root), '--inputs', str(bundle), '--native-validation', str(original),
                '--native-followup', str(followup), '--output', str(controller_out)],
            'driver03 original failed controller invocation differs')
    require(strict_json(driver['integrate.stderr.log']['raw']) == failure,
            'driver03 original controller stderr differs from its failure receipt')
    driver_failure, driver_status, packed = (json_member(driver, name) for name in ('failure.json', 'status.json', 'bundle.json'))
    require(driver_failure.get('reason') == "RuntimeError('integrate actual exit 2')"
            and driver_failure.get('complete') is False and driver_failure.get('published') is False
            and driver_failure.get('security_status') == 'HOLD'
            and driver_status.get('stage') == 'driver' and driver_status.get('phase') == 'failed'
            and driver_status.get('exit_code') == 2, 'driver03 original terminal failure differs')
    require(packed.get('archive_sha256') == P.BUNDLE_SHA and packed.get('member_count') == 14
            and packed.get('controller_sha256') == P.CONTROLLER_SHA
            and packed.get('native_runner_sha256') == P.NATIVE_SHA
            and driver['validate_binding_native.py']['sha256'] == P.NATIVE_SHA,
            'driver03 frozen bundle or unexecuted native runner changed')
    check_command_references(driver)
    return {'source': C3, 'tree': C3_TREE, 'checks_recorded': 29, 'zero_exits': 25, 'nonzero_exits': 4,
            'failed_checks': failed, 'all_c3_checks_passed': False, 'driver_integration_exit_code': 2,
            'native_child_executed': False,
            'completion_summary_created': False, 'source_bracket_identical': True,
            'raw_summary_sha256': controller['validation-01-summary.json']['sha256'],
            'raw_controller_failure_sha256': controller['failure.json']['sha256'],
            'raw_driver_failure_sha256': driver['failure.json']['sha256'], 'security_status': 'HOLD'}


def validate_merge(files, root):
    require('failure.json' not in files, 'source-only merge has a retained failure')
    summary, status = (json_member(files, name) for name in ('summary.json', 'status.json'))
    require(files['summary.json']['sha256'] == MERGE_SUMMARY_SHA
            and files['source-merged.json']['sha256'] == MERGED_SOURCE_SHA
            and files['corpus-verification/source-binding-verification.json']['sha256'] == MERGE_CORPUS_SHA,
            'the actual source-only M1 receipts differ')
    require(summary.get('schema') == 'pon-reviewed-upstream-merge-v1'
            and summary.get('merged_source') == M1 and summary.get('merged_tree') == M1_TREE
            and summary.get('first_parent') == C3 and summary.get('second_parent') == UPSTREAM
            and summary.get('source_integration_complete') is True
            and summary.get('source_binding_verified') is True
            and summary.get('recorder_sha256') == MERGE_RECORDER_SHA,
            'actual M1 source-only merge identity differs')
    for key in ('historical_c3_checks_passed', 'historical_c2_full_node_suite_passed',
                'merged_native_tests_executed', 'merged_required_checks_complete',
                'published', 'open_consensus_qualified', 'production_activation'):
        require(summary.get(key) is False, 'source-only merge inherited a test claim: ' + key)
    require(summary.get('security_status') == 'HOLD' and status.get('stage') == 'source-integration-complete'
            and status.get('phase') == 'finished' and status.get('exit_code') == 0 and status.get('source') == M1,
            'actual source-only merge did not finish')
    identity = json_member(files, 'source-merged.json')
    require(identity.get('schema') == 'trnm-ci-source-v1' and identity.get('kind') == 'head'
            and identity.get('candidate') == identity.get('tested_commit') == M1
            and identity.get('tested_tree') == M1_TREE and identity.get('tracked_worktree_verified') is True
            and identity.get('tests_executed_by_identity_check') is False, 'M1 merged identity receipt differs')
    rows = terminal_rows(files)
    require(all(row.get('cwd') == str(root) and row.get('launch_error') is None
                and row['exit_code'] in ((0, 1) if row['label'] == 'ordinary-merge-no-commit' else (0,))
                for row in rows), 'actual source merge command failures exceed the retained merge-conflict observation')
    return {'source': M1, 'tree': M1_TREE, 'parents': [C3, UPSTREAM], 'source_binding_verified': True,
            'summary_sha256': MERGE_SUMMARY_SHA, 'source_identity_sha256': MERGED_SOURCE_SHA,
            'corpus_verification_sha256': MERGE_CORPUS_SHA, 'native_tests_executed': False,
            'required_checks_executed_by_merge': False, 'security_status': 'HOLD'}


def validate_historical_lock(files, raw_input, root):
    require('failure.json' not in files, 'historical object preparation has a retained failure')
    summary = json_member(files, 'summary.json')
    require(files['summary.json']['sha256'] == HYDRATE_SUMMARY_SHA
            and summary.get('schema') == 'pon-historical-lock-materialization-v1'
            and summary.get('complete') is True and summary.get('source_commit') == C3
            and summary.get('recorder_sha256') == HYDRATE_RECORDER_SHA
            and summary.get('historical_commit') == V.HISTORICAL_LOCK[0]
            and summary.get('historical_blob') == V.HISTORICAL_LOCK_BLOB
            and summary.get('bytes') == len(raw_input) == 40365
            and summary.get('sha256') == sha(raw_input) == V.HISTORICAL_LOCK[2]
            and blob(raw_input) == V.HISTORICAL_LOCK_BLOB, 'exact historical lock preparation differs')
    require(summary.get('current_head_tree_index_status_and_shallow_state_identical') is True
            and summary.get('git_ref_mutation_commands_executed') == []
            and summary.get('project_source_changed') is False
            and summary.get('object_store_write_performed') is True
            and summary.get('native_tests_executed') is False
            and summary.get('historical_15_second_read_passed') is True
            and summary.get('original_failed_read_retained') is True,
            'historical object preparation was relabeled as tests or source changes')
    rows = terminal_rows(files)
    require(all(row['exit_code'] == 0 and row.get('cwd') == str(root)
                and row.get('launch_error') is None for row in rows), 'historical object preparation command failed')
    labels = ['project-preflight', *['before-' + item for item in ('head', 'tree', 'status', 'index-flags', 'shallow')],
              'historical-commit', 'historical-path-identity', 'materialize-exact-blob', 'original-historical-read',
              *['after-' + item for item in ('head', 'tree', 'status', 'index-flags', 'shallow')]]
    require([row['label'] for row in rows] == labels, 'historical object preparation roster differs')
    for item in ('head', 'tree', 'status', 'index-flags', 'shallow'):
        require(files['before-' + item + '.stdout.log']['raw'] == files['after-' + item + '.stdout.log']['raw'],
                'historical object preparation changed original source state')
    require(files['original-historical-read.stdout.log']['raw'] == raw_input
            and files['before-head.stdout.log']['raw'].strip() == C3.encode(), 'original historical read bytes differ')
    materialize = next(row for row in rows if row['label'] == 'materialize-exact-blob')
    require(materialize.get('argv') == ['git', 'hash-object', '-w', '--stdin']
            and materialize.get('stdin') == {'bytes': len(raw_input), 'sha256': sha(raw_input)},
            'historical exact-blob input differs')
    require(git(root, 'show', V.HISTORICAL_LOCK[0] + ':' + V.HISTORICAL_LOCK[1]) == raw_input,
            'selected historical Git object is no longer available')
    return {'source': C3, 'complete': True, 'summary_sha256': HYDRATE_SUMMARY_SHA,
            'object_store_write_performed': True, 'source_or_ref_changed': False,
            'native_tests_executed': False, 'original_failed_read_retained': True,
            'historical_blob': V.HISTORICAL_LOCK_BLOB, 'security_status': 'HOLD'}


def verify_payload_directory(root, payload):
    directory(root)
    actual = set()
    for parent, folders, files in os.walk(root, followlinks=False,
                                          onerror=lambda error: (_ for _ in ()).throw(error)):
        for name in folders:
            require(not (Path(parent) / name).is_symlink(), 'bundle directory is aliased')
        for name in files:
            path = Path(parent) / name
            key = relative(str(path.relative_to(root)))
            require(key in payload, 'unreviewed file in frozen input bundle: ' + key)
            require(read_regular(path)[0] == payload[key], 'frozen bundle member changed: ' + key)
            actual.add(key)
    require(actual == set(payload), 'frozen bundle member missing')


def driver_payload(raw, root, attempt):
    payload = P.bundle_payload(raw, historical=attempt == '01', refused=attempt == '02')
    manifest_name = {'01': P.HISTORICAL_MANIFEST, '02': P.REFUSED_MANIFEST, '03': P.BUNDLE_MANIFEST}[attempt]
    expected_controller = {'01': P.HISTORICAL_CONTROLLER_SHA, '02': P.REFUSED_CONTROLLER_SHA, '03': P.CONTROLLER_SHA}[attempt]
    manifest = strict_json(payload[manifest_name])
    require(manifest.get('frozen') is True and manifest.get('controller_sha256') == expected_controller
            and set(payload) == {row['path'] for row in manifest['files']} | {manifest_name},
            'frozen driver bundle manifest differs')
    for row in manifest['files']:
        require(len(payload[row['path']]) == row['bytes'] and sha(payload[row['path']]) == row['sha256'],
                'frozen driver bundle member differs')
    verify_payload_directory(root, payload)
    return payload


def merge_payload(packed, root):
    require(len(packed) == 165643 and sha(packed) == MERGE_ARCHIVE_SHA, 'exact source-merge archive differs')
    with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len({member.name for member in members}) == 30
                and all(member.isfile() and relative(member.name) for member in members)
                and sum(member.size for member in members) == 675426, 'source-merge archive member scope differs')
        payload = {member.name: archive.extractfile(member).read() for member in members}
    require(sha(payload['manifest.json']) == MERGE_MANIFEST_SHA, 'source-merge manifest differs')
    manifest = strict_json(payload['manifest.json'])
    require(manifest.get('frozen') is True and manifest.get('first_parent') == C3
            and manifest.get('second_parent') == UPSTREAM
            and set(payload) == {row['path'] for row in manifest['files']} | {'manifest.json'},
            'source-merge bundle source scope differs')
    for row in manifest['files']:
        require(len(payload[row['path']]) == row['bytes'] and sha(payload[row['path']]) == row['sha256'],
                'source-merge bundle member differs')
    verify_payload_directory(root, payload)
    return payload


def evidence_only(base, final, expected):
    require(base.keys() <= final.keys() and all(final[path] == entry for path, entry in base.items()),
            'E1 changed or deleted an existing M1 blob or mode')
    added = set(final) - set(base)
    require(added == set(expected) and all(path.startswith(PREFIX + '/') for path in added),
            'E1 additions exceed the exact evidence prefix members')
    for path, record in expected.items():
        require(final[path] == {'mode': '100644', 'kind': 'blob', 'git_blob': record['git_blob']},
                'E1 evidence mode or blob differs: ' + path)


def snapshot_native_retention(root, controller, original_root, followup_root):
    original, excludes_original = snapshot(original_root)
    followup, excludes_followup = snapshot(followup_root)
    outcome = P.validate_retained_native(original, followup, original_root, followup_root, root)
    entries = tree_entries(root, M1)
    retained = []
    for cohort, location, files in (('original-v3', original_root, original), ('followup-v4', followup_root, followup)):
        prefix = P.NATIVE_PREFIX + '/' + cohort + '/'
        require({name.removeprefix(prefix) for name in entries if name.startswith(prefix)} == set(files),
                'M1 does not retain every original C2 native observation member')
        for name, item in sorted(files.items()):
            path = prefix + name
            require(entries[path]['mode'] == '100644'
                    and entries[path]['git_blob'] == blob(item['raw'])
                    and git(root, 'show', M1 + ':' + path) == item['raw'], 'M1 native evidence bytes differ')
            retained.append({'path': path, 'original_source': str(location / name), **properties(item['raw'])})
        check_command_references(files)
    require(len(retained) == 121 and git(root, 'show', M1 + ':' + P.NATIVE_OBSERVATIONS)
            == controller['native-preflight.json']['raw'], 'M1 native record denominator or derived source differs')
    return original, followup, outcome, retained, {'original-v3': excludes_original, 'followup-v4': excludes_followup}


class Publisher:
    def __init__(self, args):
        self.args, self.owns_output = args, False
        self.root, self.inputs_root, self.out = args.root, args.inputs_root, args.output
        self.validation = args.validation_output
        self.merge = args.merge_output or self.inputs_root / 'upstream-merge-01'
        self.merge_inputs = args.merge_inputs or self.inputs_root / 'upstream-merge-inputs-01'
        self.lock_observations = self.inputs_root / 'historical-lock-materialization-01'
        self.controller = self.inputs_root / 'integration-03'
        self.drivers = {key: self.inputs_root / ('integration-driver-' + key) for key in ('01', '02', '03')}
        self.bundles = {key: self.inputs_root / ('integration-bundle-' + key) for key in ('01', '02', '03')}
        self.refused_controller = self.inputs_root / 'integration-02'
        self.observer = self.inputs_root / 'native-observer-audit-03'
        self.baseline = args.baseline_output
        self.baseline_followup = args.baseline_followup_output
        self.prior_publisher = args.prior_publisher or self.inputs_root / 'publish_followthrough_receipts_v2.py'
        self.validator = args.validator or self.inputs_root / 'validate_upstream_union.py'
        initialize_dependencies(self.prior_publisher, self.validator)
        self.scripts = {
            'unused-publisher-v2/publish_followthrough_receipts_v2.py': (self.prior_publisher, PRIOR_PUBLISHER_SHA),
            'merged/validate_upstream_union.py': (self.validator, VALIDATOR_SHA),
            'merged/merge_upstream_v1.py': (self.inputs_root / 'merge_upstream_v1.py', MERGE_RECORDER_SHA),
            'historical-lock/hydrate_historical_lock.py': (self.inputs_root / 'hydrate_historical_lock.py', HYDRATE_RECORDER_SHA),
            'attempt-01/remote_integration_driver_01.py': (self.inputs_root / 'remote_integration_driver_01.py', P.HISTORICAL_DRIVER_SHA),
            'attempt-02/remote_integration_driver_02.py': (self.inputs_root / 'remote_integration_driver_02.py', P.REFUSED_DRIVER_SHA),
            'attempt-03/remote_integration_driver_03.py': (self.inputs_root / 'remote_integration_driver_03.py', P.DRIVER_SHA),
            'native/run_native_validation_v3.py': (self.inputs_root / 'run_native_validation_v3.py', P.ORIGINAL_NATIVE_RUNNER_SHA),
            'native/run_native_followup_v4.py': (self.inputs_root / 'run_native_followup_v4.py', P.FOLLOWUP_SHA),
            'observer/run_native_observer_audit_v3.py': (self.inputs_root / 'run_native_observer_audit_v3.py', P.OBSERVER_RUNNER_SHA),
            'observer/integrate_candidate_v3_observer.py': (self.inputs_root / 'integrate_candidate_v3_observer.py', P.OBSERVER_CONTROLLER_SHA),
            'baseline/run_baseline_two_controls.py': (args.baseline_runner, P.BASELINE_RUNNER_SHA),
            'baseline/run_baseline_two_controls_v2.py': (args.baseline_followup_runner, P.BASELINE_FOLLOWUP_RUNNER_SHA),
        }
        self.directories = {'merged-source': self.merge, 'merged-validation': self.validation,
            'historical-orchestration/attempt-03/controller-output': self.controller,
            'historical-orchestration/attempt-02/controller-output': self.refused_controller,
            'observer-audit-03': self.observer, 'baseline-controls/initial': self.baseline,
            'baseline-controls/followup-02': self.baseline_followup,
            'historical-lock-materialization': self.lock_observations,
            **{'historical-orchestration/attempt-' + key + '/driver-output': value for key, value in self.drivers.items()}}
        for path in (self.root, self.inputs_root, *self.directories.values(), *self.bundles.values(), self.merge_inputs):
            directory(path)
        directory(self.out.parent)
        require(self.out.is_absolute() and self.out == self.out.resolve(), 'publication output is aliased')
        require(not any(os.environ.get(name) for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
                'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT')),
                'external Git override refused')
        for path in (*self.directories.values(), *self.bundles.values(), self.merge_inputs):
            require(not path.is_relative_to(self.root) and not self.out.is_relative_to(path)
                    and not path.is_relative_to(self.out), 'input/output overlaps checkout or another observation')
        require(not self.out.is_relative_to(self.root) and len(set(self.directories.values())) == len(self.directories),
                'independent observation cohorts overlap')
        require(gtext(self.root, 'rev-parse', '--show-toplevel') == str(self.root), 'real Git worktree root required')
        sparse = git(self.root, 'config', '--bool', 'core.sparseCheckout', allow_failure=True)
        require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b'', b'false'), 'sparse checkout refused')
        require(all(not row or row.startswith(b'H ') for row in git(self.root, 'ls-files', '-v', '-z').split(b'\0')),
                'hidden or nonordinary index flags refused')
        self.history = P.selected_history(self.root)
        self.script_hash = sha(read_regular(Path(__file__).absolute())[0])
        self.identity = {'root': str(self.root), 'inputs_root': str(self.inputs_root),
                         'directories': {key: str(value) for key, value in self.directories.items()},
                         'bundles': {key: str(value) for key, value in self.bundles.items()},
                         'merge_inputs': str(self.merge_inputs),
                         'scripts': {key: {'path': str(value[0]), 'sha256': value[1]} for key, value in self.scripts.items()}}
        if self.out.exists():
            directory(self.out)
            self.state = strict_json(read_regular(self.out / 'state.json')[0])
            self.commands = strict_json(read_regular(self.out / 'commands.json')[0])
            require(self.state.get('schema') == 'pon-followthrough-merged-publication-state-v3'
                    and self.state.get('input_identity') == self.identity
                    and self.state.get('publisher_sha256') == self.script_hash,
                    'publication resume identity differs; retain the original output and write key')
        else:
            require(args.phase in ('prepare', 'all-local'), 'publication must start with preparation')
            self.out.mkdir(mode=0o755)
            self.commands = []
            self.state = {'schema': 'pon-followthrough-merged-publication-state-v3', 'phase': 'starting',
                'input_identity': self.identity, 'publisher_sha256': self.script_hash, 'expected_files': {},
                'pending_write': None, 'merged_source': M1, 'merged_tree': M1_TREE,
                'native_full_suite_passed': False, 'draft_only': True, 'security_status': 'HOLD',
                'open_consensus_qualified': False, 'production_activation': False}
            self.save()
        self.lock = os.open(self.out / 'publication.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        require(stat.S_ISREG(os.fstat(self.lock).st_mode), 'publication process lock is not regular')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.owns_output = True

    def save(self):
        atomic_json(self.out / 'state.json', self.state)
        atomic_json(self.out / 'commands.json', self.commands)

    def status(self, stage, phase, code=None):
        atomic_json(self.out / 'status.json', {'schema': 'pon-followthrough-merged-publication-status-v3',
            'stage': stage, 'phase': phase, 'exit_code': code, 'recorded_unix_ns': time.time_ns(),
            'merged_source': M1, 'evidence_child': self.state.get('e1'),
            'pending_write': self.state.get('pending_write'), 'native_full_suite_passed': False,
            'draft_only': True, 'security_status': 'HOLD'})

    def run(self, label, argv, *, required=True, timeout=1800, input_bytes=None):
        label = f'{len(self.commands) + 1:03d}-' + label
        require(re.fullmatch('[A-Za-z0-9_.-]+', label), 'unsafe command label')
        stdout, stderr = self.out / (label + '.stdout.log'), self.out / (label + '.stderr.log')
        if input_bytes is not None:
            require(type(input_bytes) is bytes, 'explicit stdin must be bytes')
            write_new(self.out / (label + '.stdin.txt'), input_bytes)
        start, process, error, timed_out = time.time_ns(), None, None, False
        self.status(label, 'running')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                process = subprocess.Popen(argv, cwd=self.root, env=P.ENV, stdin=subprocess.PIPE if input_bytes is not None else None,
                                           stdout=out, stderr=err, start_new_session=True)
                process.communicate(input_bytes, timeout=timeout)
                code = process.returncode
            except subprocess.TimeoutExpired as failure:
                error, timed_out, code = repr(failure), True, 124
                V.Recorder.stop_owned(process)
            except OSError as failure:
                error, code = repr(failure), 127
            except (KeyboardInterrupt, InterruptedError) as failure:
                error, code = repr(failure), 130
                if process is not None:
                    V.Recorder.stop_owned(process)
        row = {'label': label, 'argv': [str(value) for value in argv], 'cwd': str(self.root), 'exit_code': code,
               'process_exit_code': process.returncode if process is not None else None,
               'start_unix_ns': start, 'end_unix_ns': time.time_ns(), 'launch_error': error,
               'timed_out': timed_out, 'timeout_seconds': timeout}
        for stream, path in (('stdout', stdout), ('stderr', stderr)):
            row[stream] = {'file': path.name, **properties(read_regular(path)[0])}
        if input_bytes is not None:
            row['stdin'] = {'file': label + '.stdin.txt', **properties(input_bytes)}
        self.commands.append(row)
        self.save()
        self.status(label, 'finished' if code == 0 else 'failed', code)
        require(not required or code == 0, 'actual command failed; original streams retained: ' + label)
        return row

    def output_json(self, row):
        return strict_json(read_regular(self.out / row['stdout']['file'])[0])

    def current_branch(self):
        branch = gtext(self.root, 'symbolic-ref', '--short', 'HEAD')
        require(branch == BRANCH, 'publication may use only the reviewed root branch')
        return branch

    def source_guard(self):
        require(sha(read_regular(Path(__file__).absolute())[0]) == self.script_hash, 'publisher changed during execution')
        require(sha(read_regular(self.prior_publisher)[0]) == PRIOR_PUBLISHER_SHA
                and sha(read_regular(self.validator)[0]) == VALIDATOR_SHA, 'loaded pinned helper changed')

    def verify_tree(self, revision):
        evidence_only(tree_entries(self.root, M1), tree_entries(self.root, revision), self.state['expected_files'])
        for path, record in self.state['expected_files'].items():
            require(properties(git(self.root, 'show', revision + ':' + path)) == record,
                    'actual Git stored E1 bytes differ: ' + path)

    def working_guard(self, *, allow_partial=False):
        self.source_guard()
        require(self.current_branch() == self.state['branch']
                and gtext(self.root, 'rev-parse', 'HEAD') == self.state['expected_head'],
                'root branch or HEAD changed outside publication')
        require(all(not row or row.startswith(b'H ') for row in git(self.root, 'ls-files', '-v', '-z').split(b'\0')),
                'index concealment flags changed')
        if self.state['phase'] not in ('starting', 'preparing', 'prepared', 'committing'):
            require(gtext(self.root, 'write-tree') == self.state['prepared_tree'], 'E1 index changed')
        changed = {name.decode() for name in (git(self.root, 'diff', '--name-only', '-z', 'HEAD', '--')
                   + git(self.root, 'ls-files', '--others', '--exclude-standard', '-z')).split(b'\0') if name}
        require(changed <= set(self.state['expected_files']), 'unreviewed working-tree changes exist')
        for path, record in self.state['expected_files'].items():
            target = self.root / path
            if allow_partial and not target.exists():
                require(not target.is_symlink(), 'dangling artifact alias')
                continue
            require(properties(read_regular(target)[0]) == record, 'prepared evidence changed: ' + path)

    def prepare(self):
        require(self.state['phase'] in ('starting', 'preparing'), 'preparation cannot replace a completed phase')
        self.status('prepare', 'running')
        self.source_guard()
        require(gtext(self.root, 'rev-parse', 'HEAD') == M1 and gtext(self.root, 'rev-parse', M1 + '^{tree}') == M1_TREE
                and gtext(self.root, 'rev-list', '--parents', '-n', '1', M1).split() == [M1, C3, UPSTREAM],
                'publication must start at the actual independently validated M1')
        require(gtext(self.root, 'rev-parse', C3 + '^{tree}') == C3_TREE
                and gtext(self.root, 'rev-list', '--parents', '-n', '1', C3).split() == [C3, C2],
                'failed C3 parent identity differs')
        require(not (self.inputs_root / 'binding-native-03').exists(),
                'attempt03 native child exists although the recorded driver stopped before it')
        branch = self.current_branch()
        if self.state['phase'] == 'starting':
            require(not git(self.root, 'status', '--porcelain') and not (self.root / PREFIX).exists(),
                    'initial M1 must be clean and the E1 evidence prefix absent')
        else:
            self.working_guard(allow_partial=True)
        before_entries = tree_entries(self.root, M1)
        V.evidence_union(tree_entries(self.root, C3), tree_entries(self.root, UPSTREAM), before_entries)
        require(git(self.root, 'show', BASE + ':' + VERIFY) == git(self.root, 'show', M1 + ':' + VERIFY),
                'original source verifier changed')
        source_lock = os.open(self.controller / 'controller.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        require(stat.S_ISREG(os.fstat(source_lock).st_mode), 'original controller lock is not regular')
        fcntl.flock(source_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        try:
            snapshots, exclusions = {}, {}
            for label, path in self.directories.items():
                allowed_nul = ('before-index-flags.stdout.log', 'after-index-flags.stdout.log') if label == 'historical-lock-materialization' else ()
                snapshots[label], exclusions[label] = snapshot(path, nul_logs=allowed_nul)
            controller = snapshots['historical-orchestration/attempt-03/controller-output']
            state = json_member(controller, 'state.json')
            require(state.get('schema') == 'pon-followthrough-controller-state-v2'
                    and state.get('controller_sha256') == P.CONTROLLER_SHA and state.get('root') == str(self.root)
                    and state.get('inputs') == str(self.bundles['03']), 'actual C3 controller source identity differs')
            original_root, followup_root = Path(state['native_validation']), Path(state['native_followup'])
            for path in (original_root, followup_root):
                directory(path)
                require(not path.is_relative_to(self.root) and not self.out.is_relative_to(path)
                        and not path.is_relative_to(self.out), 'original native output overlaps checkout or publication receipts')
            original, followup, native_retention, native_members, native_exclusions = snapshot_native_retention(
                self.root, controller, original_root, followup_root)
            require(followup['summary.json']['raw'] == snapshots['historical-orchestration/attempt-03/driver-output']['observed-native-followup-summary.json']['raw']
                    == snapshots['historical-orchestration/attempt-02/driver-output']['observed-native-followup-summary.json']['raw'],
                    'an original driver changed the original followup summary bytes')
            script_raw = {}
            for name, (path, expected_sha) in self.scripts.items():
                raw = read_regular(path)[0]
                require(sha(raw) == expected_sha, 'original orchestration script differs: ' + name)
                script_raw[name] = raw
            payloads = {key: driver_payload(script_raw['attempt-' + key + '/remote_integration_driver_' + key + '.py'],
                                           self.bundles[key], key) for key in ('01', '02', '03')}
            manifest = json_member(controller, 'input-manifest.json')
            require(manifest == state.get('input_sha256')
                    and all(path in payloads['03'] and sha(payloads['03'][path]) == digest for path, digest in manifest.items()),
                    'actual C3 helper input identities differ')
            archive_path = self.inputs_root / 'upstream-merge-inputs-01.tar.gz'
            archive_raw = read_regular(archive_path)[0]
            merged_payload = merge_payload(archive_raw, self.merge_inputs)
            historical_input_path = self.inputs_root / 'historical-Cargo-lock-7dd.bytes'
            historical_input_raw = read_regular(historical_input_path)[0]
            observations = {
                'merged_source': validate_merge(snapshots['merged-source'], self.root),
                'merged_validation': validate_merged_controls(snapshots['merged-validation'], self.root, self.validation,
                                                              snapshots['merged-source']),
                'failed_c3': validate_failed_c3(controller, snapshots['historical-orchestration/attempt-03/driver-output'],
                    self.root, self.controller, self.bundles['03'], original_root, followup_root),
                'original_driver_01': P.validate_historical_driver(snapshots['historical-orchestration/attempt-01/driver-output']),
                'refused_controller_02': P.validate_refused_integration(
                    snapshots['historical-orchestration/attempt-02/driver-output'],
                    snapshots['historical-orchestration/attempt-02/controller-output'], self.root,
                    self.bundles['02'], self.refused_controller, original_root, followup_root),
                'readonly_observer': P.validate_readonly_observer(snapshots['observer-audit-03'], self.root,
                    self.inputs_root / 'integrate_candidate_v3_observer.py', original_root, followup_root),
                'baseline_controls': P.validate_baseline_observations(snapshots['baseline-controls/initial'],
                    snapshots['baseline-controls/followup-02'], self.baseline, self.baseline_followup, self.root),
                'historical_object_preparation': validate_historical_lock(snapshots['historical-lock-materialization'],
                                                                         historical_input_raw, self.root),
                'retained_c2_native': native_retention,
                'unused_v2_publisher': {'sha256': PRIOR_PUBLISHER_SHA, 'bytes': len(script_raw['unused-publisher-v2/publish_followthrough_receipts_v2.py']),
                    'publisher_completion_path_invoked': False, 'scope': 'pinned read-only helper dependency and retained unexecuted publisher'},
                'native_observation_complete': True, 'native_full_suite_passed': False,
                'm1_full_node_suite_executed': False, 'm1_full_node_suite_passed': False,
                'c3_all_checks_passed': False, 'draft_only': True,
                'baseline_observation_complete': True, 'baseline_selected_tests': 2,
                'all_baseline_tests_passed': False, 'baseline_full_library_suite_passed': None,
                'open_consensus_qualified': False, 'production_activation': False, 'security_status': 'HOLD'}
            references = {label: check_command_references(files) for label, files in snapshots.items()}
            raw_files, members = {}, []
            def add(name, raw, origin, original_mode='unknown', representation='original-bytes'):
                name = relative(name)
                if name.endswith('.md'):
                    name += '.txt'
                destination = PREFIX + '/' + name
                require(destination not in raw_files, 'archive destination collision: ' + destination)
                raw_files[destination] = raw
                members.append({'path': name, 'original_source': origin, 'original_mode': original_mode,
                                'representation': representation, **properties(raw)})
            for label, files in snapshots.items():
                for name, item in sorted(files.items()):
                    add(label + '/' + name, item['raw'], str(self.directories[label] / name), item['original_mode'])
            for key, payload in payloads.items():
                for name, raw in sorted(payload.items()):
                    add('historical-orchestration/attempt-' + key + '/bundle-members/' + name,
                        raw, str(self.bundles[key] / name))
            for name, raw in sorted(merged_payload.items()):
                add('orchestration/merged-inputs/' + name, raw, str(self.merge_inputs / name))
            for name, raw in sorted(script_raw.items()):
                add('orchestration/' + name, raw, str(self.scripts[name][0]))
            add('orchestration/historical-lock/historical-Cargo-lock-7dd.bytes.txt', historical_input_raw, str(historical_input_path))
            archive_encoded = base64.b64encode(archive_raw) + b'\n'
            require(base64.b64decode(archive_encoded, validate=False) == archive_raw, 'archive representation does not decode exactly')
            add('orchestration/merged-inputs-archive.base64.txt', archive_encoded, str(archive_path),
                representation='base64-of-original-compressed-archive; decoded identity in sources.json')
            publisher_raw = read_regular(Path(__file__).absolute())[0]
            require(sha(publisher_raw) == self.script_hash, 'publisher source changed')
            add('orchestration/publish_followthrough_merged_v3.py', publisher_raw, str(Path(__file__).absolute()))
            sources = {'schema': 'pon-followthrough-merged-evidence-sources-v3', 'code_checkpoint_c2': C2,
                'failed_binding_child_c3': C3, 'merged_source_m1': M1, 'merged_tree': M1_TREE,
                'merge_parents': [C3, UPSTREAM], 'observations': observations,
                'publisher_sha256': self.script_hash, 'prior_publisher_sha256': PRIOR_PUBLISHER_SHA,
                'validator_sha256': VALIDATOR_SHA, 'selected_history': self.history,
                'original_command_reference_closure': references, 'explicit_exclusions': exclusions,
                'retained_native_exclusions': native_exclusions, 'retained_native_members': native_members,
                'retained_native_original_directories': {'original-v3': str(original_root), 'followup-v4': str(followup_root)},
                'decoded_merge_archive_identity': {'bytes': len(archive_raw), 'sha256': sha(archive_raw),
                    'git_blob': blob(archive_raw), 'base64_path': 'orchestration/merged-inputs-archive.base64.txt'},
                'historical_driver_archive_retention': 'Each original compressed archive remains exactly embedded in its pinned driver source',
                'e1_commit_identity_recorded_after_commit': True, 'e1_only_added_prefix': PREFIX,
                'existing_m1_files_modified': False, 'native_tests_executed_by_publisher': False,
                'hosted_ci_observed_complete': False, 'native_full_suite_passed': False,
                'draft_only': True, 'open_consensus_qualified': False, 'production_activation': False,
                'security_status': 'HOLD'}
            raw_files[PREFIX + '/sources.json'] = encoded(sources)
            raw_files[PREFIX + '/README.md'] = self.readme(observations).encode()
            raw_files[PREFIX + '/members.json'] = encoded({'schema': 'pon-followthrough-merged-evidence-members-v3',
                'source_m1': M1, 'source_tree': M1_TREE, 'copied_members': members,
                'copied_count': len(members), 'copied_bytes': sum(row['bytes'] for row in members),
                'generated_members': [{'path': name.removeprefix(PREFIX + '/'), **properties(raw_files[name])}
                                      for name in (PREFIX + '/sources.json', PREFIX + '/README.md')],
                'manifest_identity': 'verified against the actual staged and committed Git tree; no self-hash asserted',
                'existing_m1_blobs_and_modes_unchanged': True, 'native_full_suite_passed': False,
                'open_consensus_qualified': False, 'production_activation': False, 'security_status': 'HOLD'})
            expected = {path: properties(raw) for path, raw in raw_files.items()}
            require(len(expected) <= MAX_MEMBERS and sum(len(raw) for raw in raw_files.values()) <= MAX_TOTAL,
                    'complete evidence collection exceeds reviewed bounds')
            if self.state['phase'] == 'preparing':
                require(self.state.get('expected_files') == expected and self.state.get('branch') == branch
                        and self.state.get('observations') == observations, 'preparation resume inputs changed')
            else:
                self.state.update(phase='preparing', branch=branch, expected_head=M1,
                                  expected_files=expected, observations=observations)
                self.save()
            self.working_guard(allow_partial=True)
            self.run('prepare-preflight', ['bash', 'scripts/project-preflight.sh'])
            for path, raw in raw_files.items():
                target = self.root / path
                if target.exists():
                    require(read_regular(target)[0] == raw, 'partial evidence copy differs: ' + path)
                else:
                    write_new(target, raw)
            for label, path in self.directories.items():
                nul = ('before-index-flags.stdout.log', 'after-index-flags.stdout.log') if label == 'historical-lock-materialization' else ()
                latest, latest_exclusions = snapshot(path, nul_logs=nul)
                require(snapshot_identity(latest) == snapshot_identity(snapshots[label])
                        and latest_exclusions == exclusions[label], 'original output changed during copying: ' + label)
            for location, files in ((original_root, original), (followup_root, followup)):
                latest, _ = snapshot(location)
                require(snapshot_identity(latest) == snapshot_identity(files), 'original C2 native records changed during copying')
            for key, payload in payloads.items():
                verify_payload_directory(self.bundles[key], payload)
            verify_payload_directory(self.merge_inputs, merged_payload)
            for name, raw in script_raw.items():
                require(read_regular(self.scripts[name][0])[0] == raw, 'original orchestration script changed during copying')
            require(read_regular(archive_path)[0] == archive_raw
                    and read_regular(historical_input_path)[0] == historical_input_raw,
                    'original archive or historical lock changed during copying')
            self.working_guard()
            paths = sorted(expected)
            for offset in range(0, len(paths), 100):
                self.run('stage-explicit-raw-evidence', ['git', 'add', '-f', '--', *paths[offset:offset + 100]])
            tree = gtext(self.root, 'write-tree')
            self.verify_tree(tree)
            require(not git(self.root, 'diff', '--name-only'), 'unstaged changes remain after exact evidence staging')
            self.state.update(phase='prepared', prepared_tree=tree)
            self.save()
            self.status('prepare', 'finished', 0)
        finally:
            os.close(source_lock)

    def readme(self, observations):
        return f'''# Merged checks and retained failed observations

Status: **draft review only; security HOLD; native full-suite success is false**.

This evidence-only child preserves every existing blob and mode in M1
`{M1}` (tree `{M1_TREE}`). It adds this directory only. The E1 commit identity
and its own repository/source checks are recorded by the publication recorder
after the commit exists; this document does not anticipate those outcomes.

## Separate source and execution scopes

* **C2 `{C2}`** retains the original full node-library result: exit **101**,
  **1,285 passed / 2 failed / 39 original ignored**. Its original-v3 files remain
  in [the original command directory](../native/original-v3/commands.json).
  No nonexistent v3 summary or source-after record is manufactured. The
  [independent v4 followup](../native/followup-v4/summary.json) retains two exact
  original test failures (exit 101), while its other twelve commands exited 0.
  Its source-before/source-after bytes equal the original v3 before record.
  Limited focused successes, fresh-probe observations and Clippy remain C2
  observations; they do not replace the failed full suite.
* **C3 `{C3}`** actually completed 29 source-bracketed checks: **25 zero exits,
  4 nonzero exits**. The [original summary](historical-orchestration/attempt-03/controller-output/validation-01-summary.json)
  and [all original commands](historical-orchestration/attempt-03/controller-output/commands.json)
  retain the CI-contract/repository failures caused by the stale inline store
  pin, and the ledger negative-control failure caused by a missing historical
  Cargo.lock blob. Driver03 failed and did **not execute its native child**.
  Its unexecuted runner is retained as source, without execution credit.
* **M1 `{M1}`** is the normal two-parent merge of C3 and upstream `{UPSTREAM}`.
  [Source-only merge receipts](merged-source/summary.json) record that merge
  and its exact corpus/parent binding. They claim no tests. The independently
  executed [38-command validation](merged-validation/summary.json) and
  [raw command list](merged-validation/commands.json) have all required exits
  zero and an identical M1 source bracket. This includes the retained 18 CI
  names and 19 ledger names, corpus/CI/repository/source/report checks, locked
  offline metadata, format, the MVCC library, the nine quorum integration
  tests, the exact cancellation test, four confirmation controls, and strict
  Clippy for four owners with default features and all targets. The full node
  library suite was **not repeated**. Neither parent contributes test credit
  to this cohort, and no hosted Actions completion is claimed.
* **E1** adds original receipts only under `{PREFIX}/`. Every pre-existing
  M1 blob and mode remains identical. Its separately recorded source and
  repository checks do not rerun or upgrade C2, C3, baseline or M1 tests.

## Retained independent controls and prior attempts

The [initial baseline attempt](baseline-controls/initial/failure.json) stopped
before tests because an orchestration guard refused shallow history. The
[baseline followup](baseline-controls/followup-02/summary.json) ran only two
unchanged selected tests: large-parent passed; inactive-page failed with
`PUBLIC_MUTATION_CPU_BUDGET`. Its full-library success remains null. This is
different from the `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH` diagnostic failure in
C2's full run. C2's separate exact reruns both reported CPU-budget failures.
These controls establish neither identical causes nor absence of regression.

Historical orchestration attempts 01, 02 and 03 have separate original output
and bundle directories. Attempt01 stopped at the failed C2 native gate;
attempt02 stopped at its test-count parser refusal; attempt03 created C3 but
failed its own checks. No later observation rewrites any of those outcomes.
The [read-only observer audit](observer-audit-03/summary.json) inspected the
39 original plus 14 followup commands and 121 raw members. It executed no
native tests and created no C3. The original publisher v2 is retained under
`orchestration/unused-publisher-v2/`; its completion path was never invoked.
This publisher loads only its pinned read-only helpers.

[Historical object preparation](historical-lock-materialization/summary.json)
retains the exact 40,365-byte Cargo.lock from its existing selected Git commit
and tree. It restored only that authenticated blob, left HEAD/tree/index/status
and shallow state identical, and ran no native tests. Its original failed C3
read remains recorded. M1 independently passed the unchanged 19 ledger controls.

## Byte preservation and limits

[members.json](members.json) identifies each copied byte count, SHA-256, Git
blob, original source and representation. [sources.json](sources.json) records
command-stream closure, every already-retained C2 member, exact orchestration
identities, and explicit temporary-index/lock exclusions. Historical Markdown
bytes use `.md.txt` names. The source-merge compressed archive is retained as
base64 with an explicit decoded original identity; each old driver's archive
also remains exactly embedded in its pinned source. Two NUL-delimited original
Git index-flag logs are preserved as raw logs, not as executable binaries.

Global shallow history is disclosed; complete global history is not claimed.
Required selected objects, parent paths and materialized source remain checked.
This evidence establishes no cheapest legal work-cost bound, QROM reduction,
public-prefix/chain-growth/chain-quality bound, confirmation failure probability,
model benefit or production qualification. All qualifications remain
**HOLD/false/null**. The candidate remains a draft for review.
'''

    def adopt_commit(self):
        head = gtext(self.root, 'rev-parse', 'HEAD')
        require(gtext(self.root, 'rev-list', '--parents', '-n', '1', head).split() == [head, M1]
                and gtext(self.root, 'rev-parse', head + '^{tree}') == self.state['prepared_tree']
                and gtext(self.root, 'log', '-1', '--format=%s', head) == COMMIT_MESSAGE,
                'pending local evidence commit cannot be reconciled')
        self.verify_tree(head)
        require(not git(self.root, 'status', '--porcelain'), 'E1 is not clean after commit')
        self.state.update(phase='committed', e1=head, expected_head=head, pending_write=None)
        self.save()

    def commit(self):
        require(self.state['phase'] in ('prepared', 'committing'), 'commit requires exactly prepared evidence')
        if self.state['phase'] == 'committing' and gtext(self.root, 'rev-parse', 'HEAD') != M1:
            self.adopt_commit()
            self.status('commit-reconciled', 'finished', 0)
            return
        self.working_guard()
        require(gtext(self.root, 'write-tree') == self.state['prepared_tree'], 'prepared index changed')
        self.verify_tree(self.state['prepared_tree'])
        self.run('commit-preflight', ['bash', 'scripts/project-preflight.sh'])
        self.working_guard()
        self.state.update(phase='committing', pending_write={'kind': 'local-commit', 'parent': M1,
                                                          'tree': self.state['prepared_tree']})
        self.save()
        self.run('commit-evidence-only-child', ['git', 'commit', '-m', COMMIT_MESSAGE])
        self.adopt_commit()
        self.status('commit', 'finished', 0)

    def validate(self):
        require(self.state['phase'] in ('committed', 'validation_failed', 'validated'), 'validation requires actual E1')
        self.working_guard()
        self.verify_tree(self.state['e1'])
        require(not git(self.root, 'status', '--porcelain'), 'E1 validation requires a clean checkout')
        require(git(self.root, 'show', BASE + ':' + VERIFY) == read_regular(self.root / VERIFY)[0],
                'original source verifier changed')
        attempt = len(self.state.get('validation_runs', [])) + 1
        prefix = f'e1-validation-{attempt:02d}'
        before, after = self.out / (prefix + '-before.json'), self.out / (prefix + '-after.json')
        first = len(self.commands)
        source = [sys.executable, '-B', VERIFY, '--kind', 'head', '--expected-head', self.state['e1'], '--output']
        for label, argv in (
            ('preflight', ['bash', 'scripts/project-preflight.sh']),
            ('source-before', source + [str(before)]),
            ('repository-and-markdown', [sys.executable, '-B', 'scripts/ci/check_repository.py']),
            ('generated-metadata-whitespace', ['git', 'diff', '--check', M1, self.state['e1'], '--',
                PREFIX + '/README.md', PREFIX + '/members.json', PREFIX + '/sources.json']),
            ('source-after', source + [str(after)]),
            ('source-identical', ['cmp', str(before), str(after)]),
        ):
            self.working_guard()
            self.run(prefix + '-' + label, argv, required=False)
        rows = self.commands[first:]
        success = len(rows) == 6 and all(row['exit_code'] == 0 and row['launch_error'] is None for row in rows)
        if success:
            bracket = {path.name: {'raw': read_regular(path)[0]} for path in (before, after)}
            original_bracket(bracket, before.name, after.name, self.state['e1'], self.state['prepared_tree'])
        self.working_guard()
        self.verify_tree(self.state['e1'])
        require(not git(self.root, 'status', '--porcelain'), 'E1 checks changed the checkout')
        result = {'schema': 'pon-followthrough-merged-evidence-child-checks-v3', 'complete': success,
            'source_m1': M1, 'source_tree': M1_TREE, 'evidence_child_e1': self.state['e1'],
            'e1_tree': self.state['prepared_tree'], 'all_existing_m1_blobs_and_modes_unchanged': True,
            'only_added_prefix': PREFIX, 'copied_raw_bytes_unchanged': True,
            'm1_required_checks_passed': True, 'c3_required_checks_passed': False,
            'native_tests_reexecuted': False, 'm1_full_node_suite_executed': False,
            'native_full_suite_passed': False, 'hosted_ci_observed_complete': False,
            'draft_only': True, 'open_consensus_qualified': False, 'production_activation': False,
            'commands': [{'label': row['label'], 'exit_code': row['exit_code']} for row in rows],
            'security_status': 'HOLD'}
        write_new(self.out / (prefix + '-summary.json'), encoded(result))
        self.state.setdefault('validation_runs', []).append({'path': prefix + '-summary.json', 'complete': success})
        self.state['phase'] = 'validated' if success else 'validation_failed'
        self.save()
        self.status('validate', 'finished' if success else 'failed', 0 if success else 2)
        require(success, 'E1 source/repository checks failed; no publication attempted')

    def github_identity(self):
        value = self.output_json(self.run('github-user', ['gh', 'api', 'user', '--jq', '{login: .login}']))
        require(value.get('login') == ACCOUNT, 'GitHub write identity is not ProfHepta')

    def push_origin(self):
        origins = gtext(self.root, 'remote', 'get-url', '--all', '--push', 'origin').splitlines()
        require(len(origins) == 1 and origins[0] in (f'https://github.com/{REPOSITORY}.git',
                f'https://github.com/{REPOSITORY}', f'git@github.com:{REPOSITORY}.git'),
                'origin does not have exactly the reviewed canonical push target')
        return origins[0]

    def remote_tip(self):
        # The frozen helper reads the checked push URL itself, never another fetch URL.
        return P.Publisher.remote_tip(self)

    def find_pr(self):
        return P.Publisher.find_pr(self)

    def observe_base(self):
        row = self.run('draft-base-read', ['git', 'ls-remote', '--heads', self.push_origin(), 'refs/heads/' + PR_BASE])
        lines = read_regular(self.out / row['stdout']['file'])[0].decode().splitlines()
        require(len(lines) == 1, 'draft base lookup is absent or ambiguous')
        oid, ref = lines[0].split()
        require(re.fullmatch('[0-9a-f]{40}', oid) and ref == 'refs/heads/' + PR_BASE, 'draft base ref differs')
        comparison_row = self.run('draft-base-comparison', ['gh', 'api', '--method', 'GET',
            f'repos/{REPOSITORY}/compare/{BASE}...{oid}'])
        comparison = self.output_json(comparison_row)
        require(comparison.get('base_commit', {}).get('sha') == BASE
                and comparison.get('status') in ('ahead', 'behind', 'diverged', 'identical')
                and type(comparison.get('ahead_by')) is int and comparison['ahead_by'] >= 0
                and type(comparison.get('behind_by')) is int and comparison['behind_by'] >= 0,
                'actual draft base comparison identity/counters unavailable')
        observation = {'ref': PR_BASE, 'head': oid, 'command': row['label'], 'observed_unix_ns': row['end_unix_ns'],
            'selected_baseline': BASE, 'reviewed_merged_second_parent': UPSTREAM,
            'comparison_command': comparison_row['label'], 'base_relationship': comparison['status'],
            'ahead_by': comparison['ahead_by'], 'behind_by': comparison['behind_by'],
            'base_advanced_since_source_checkpoint': comparison['ahead_by'] > 0,
            'observed_base_matches_reviewed_merge_parent': oid == UPSTREAM,
            'validated_merge_contains_reviewed_parent': True,
            'integration_against_observed_base_verified': oid == UPSTREAM,
            'moved_base_tests_inherited': False, 'hosted_ci_observed_complete': False}
        self.state.setdefault('base_observations', []).append(observation)
        self.save()
        return observation

    def pr_body(self):
        observed = self.state['publication_base_observation']
        require(observed.get('ref') == PR_BASE and re.fullmatch('[0-9a-f]{40}', observed.get('head', ''))
                and observed.get('validated_merge_contains_reviewed_parent') is True
                and observed.get('moved_base_tests_inherited') is False,
                'concrete publication base observation missing or upgraded')
        advanced = str(observed['base_advanced_since_source_checkpoint']).lower()
        same_base = str(observed['observed_base_matches_reviewed_merge_parent']).lower()
        return f'''{MARKER}
## Draft status and original failures

This candidate remains **HOLD**. C2's full node-library suite exited **101**,
with **1,285 passed / 2 failed / 39 original ignored**. Both separately selected
original exact reruns also failed. C3 then completed 29 checks with **25 zero
exits and 4 nonzero exits**; its driver stopped before the native child.
All original failures and raw records remain unchanged. No project CI,
internal CPU budget, deadline, test assertion or qualification flag was relaxed.

## Changes

Native payment/effect reobservation rechecks its persistent journal after
callbacks. Confirmation observation checks retained cumulative work and its
genesis anchor, then fences the final storage epoch. The branch registers the
native evidence readers and retains source mappings with their historical
limits. M1 normally merges the independent upstream evaluation-quorum work,
preserves both sides' original evidence and test names, fixes the stale inline
store pin, and retains the exact historical object needed by an existing
ledger negative control. Unknown and owner-stop semantics remain required.

## Source-specific observations

- **C2 `{C2}`** retains its original failed full suite, prior focused red/green
  controls and their exact counterfactual limits. The independent v4 followup
  has fourteen actual commands: two exact-test failures and twelve zero exits,
  including strict Clippy, format and fresh-probe/reader observations. Its
  before/after source bytes equal the original v3 before receipt. No missing
  v3 summary or source-after record was manufactured.
- **C3 `{C3}`** retains its failed 29-command cohort. Three failures concerned
  the stale inline store pin; the fourth concerned a missing historical
  Cargo.lock object. The old native child did not execute. Restoring the exact
  historical Git blob was an object-preparation action, not a test result.
- **M1 `{M1}`**, tree `{M1_TREE}`, has exact ordered parents `[C3, {UPSTREAM}]`.
  Its independent 38-command cohort passed with an identical source bracket:
  original corpus/CI/repository/report checks, all 18 retained CI test names,
  all 19 ledger names, locked offline metadata, format, MVCC library, nine
  quorum integration tests, one exact cancellation test, four confirmation
  controls and four-owner strict Clippy (default features, all targets).
  **The full node library suite was not rerun and is not reported as passed.**
  Neither parent's test results count as M1 executions.
- **E1 `{self.state['e1']}`** adds original evidence only under `{PREFIX}/`.
  Every existing M1 Git blob and mode is identical. E1's own source and
  repository/Markdown checks passed separately; they do not upgrade any
  earlier native outcome.

The independent exact-baseline controls observed large-parent passing and
inactive-page failing with `PUBLIC_MUTATION_CPU_BUDGET`; only those two tests
ran, so baseline full-library success remains null. C2's full-run inactive-page
diagnostic instead failed with `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH`; its isolated
reruns reported CPU-budget failures. These observations establish neither a
shared cause nor absence of regression.

## Actual base and publication scope

The publication recorder observed `{PR_BASE}` at `{observed['head']}`.
M1 includes the reviewed upstream `{UPSTREAM}` through its normal second
parent. `base_advanced_since_source_checkpoint={advanced}`;
`observed_base_matches_reviewed_merge_parent={same_base}`. If the remote base
has advanced further, that newer integration is not validated by this cohort.
The exact PR readback base is also recorded. No tests from PR #847 or another
branch are inherited, and no merge to main or production activation is requested.

[Complete retained evidence](https://github.com/{REPOSITORY}/blob/{self.state['e1']}/{PREFIX}/README.md)
contains M1 merge/validation outputs, C3's full failed outputs, old attempts01/02,
the parser-only observer audit, both independent baseline attempts, historical
object preparation and their pinned original orchestration. The original C2
121 raw members remain in the parent evidence. Manifests bind byte counts,
SHA-256 and Git blobs. The unused v2 publisher remains unchanged; its success
path was not executed. Global shallow history is disclosed, while selected
source objects and parent paths remain mandatory.

This is a draft for review. Hosted GitHub Actions completion is not asserted.
No QROM reduction, cheapest legal work-cost bound, public consensus guarantee,
confirmation-failure probability, model benefit or production qualification is
established. Qualification remains **HOLD/false/null**.
'''

    def finish_pr(self, value, body):
        require(value is not None and value.get('draft') is True and value.get('state') == 'open'
                and value.get('head', {}).get('sha') == self.state['e1']
                and value.get('head', {}).get('ref') == BRANCH
                and value.get('head', {}).get('repo', {}).get('full_name') == REPOSITORY
                and value.get('base', {}).get('ref') == PR_BASE
                and re.fullmatch('[0-9a-f]{40}', value.get('base', {}).get('sha', ''))
                and value.get('user', {}).get('login') == ACCOUNT
                and value.get('title') == TITLE and value.get('body') == body,
                'draft PR readback differs from the concrete publication payload')
        base_head = value['base']['sha']
        self.state.update(phase='published', pending_write=None,
            pull_request={'number': value['number'], 'url': value['html_url'], 'draft': True,
                'head': self.state['e1'], 'base': PR_BASE, 'readback_base_head': base_head,
                'readback_base_matches_observed': base_head == self.state['publication_base_observation']['head'],
                'readback_base_matches_reviewed_merge_parent': base_head == UPSTREAM,
                'integration_against_readback_base_verified': base_head == UPSTREAM,
                'moved_base_tests_inherited': False})
        self.save()
        self.status('publish', 'finished', 0)

    def publish(self):
        require(self.state['phase'] in ('validated', 'pushed', 'publication_unknown', 'published'),
                'publication requires actual completed E1 checks')
        require(self.state.get('validation_runs') and self.state['validation_runs'][-1]['complete'] is True,
                'E1 source/repository checks are incomplete')
        observations = self.state.get('observations', {})
        plain_scope(observations)
        require(observations.get('merged_validation', {}).get('all_required_checks_passed') is True
                and observations['merged_validation'].get('actual_commands') == 38
                and observations.get('failed_c3', {}).get('all_c3_checks_passed') is False
                and observations['failed_c3'].get('nonzero_exits') == 4
                and observations.get('native_full_suite_passed') is False
                and observations.get('all_baseline_tests_passed') is False
                and observations.get('baseline_full_library_suite_passed', 'missing') is None,
                'M1 actual prerequisites or historical failed scopes changed')
        self.working_guard()
        self.verify_tree(self.state['e1'])
        require(not git(self.root, 'status', '--porcelain'), 'publication checkout is not clean')
        self.run('publish-preflight', ['bash', 'scripts/project-preflight.sh'])
        self.github_identity()
        observed_base = self.observe_base()
        if 'publication_base_observation' not in self.state:
            require(self.state['phase'] == 'validated' and self.state.get('pending_write') is None,
                    'a pending publication lost its original concrete base observation')
            self.state['publication_base_observation'] = observed_base
            self.save()
        body = self.pr_body()
        existing = self.find_pr()
        if self.state['phase'] == 'published':
            require(self.remote_tip() == self.state['e1'], 'previously published branch moved')
            self.finish_pr(existing, body)
            return
        pending = self.state.get('pending_write')
        if pending and pending['kind'] in ('create-pr', 'update-pr'):
            require(pending.get('body_sha256') == sha(body.encode()), 'pending PR payload changed')
            require(self.remote_tip() == self.state['e1'], 'pending PR branch is not the published E1')
            self.finish_pr(existing, body)
            return
        remote = self.remote_tip()
        if pending:
            require(pending['kind'] == 'push' and remote == self.state['e1'],
                    'previous remote write is unconfirmed; retain this output and do not blindly replay under another key')
            self.state.update(phase='pushed', pending_write=None)
            self.save()
        elif remote != self.state['e1']:
            require(self.state['phase'] == 'validated', 'previously pushed branch moved; no blind repush')
            if remote is not None:
                git(self.root, 'cat-file', '-e', remote + '^{commit}')
                git(self.root, 'merge-base', '--is-ancestor', remote, self.state['e1'])
            self.working_guard()
            update = f'{self.state["e1"]} {self.state["e1"]} refs/heads/{BRANCH} {remote or "0" * 40}\n'.encode()
            self.run('exact-push-preflight', ['bash', 'scripts/project-preflight.sh', '--push', 'origin', self.push_origin()],
                     input_bytes=update)
            self.state.update(phase='publication_unknown', pending_write={'kind': 'push',
                'expected_head': self.state['e1'], 'prior_remote': remote})
            self.save()
            self.working_guard()
            self.run('normal-fast-forward-push', ['git', 'push', 'origin', self.state['e1'] + ':refs/heads/' + BRANCH], required=False)
            require(self.remote_tip() == self.state['e1'], 'push outcome unconfirmed; no automatic replay')
            self.state.update(phase='pushed', pending_write=None)
            self.save()
        else:
            self.state.update(phase='pushed', pending_write=None)
            self.save()
        self.working_guard()
        existing = self.find_pr()
        if (existing is not None and existing.get('head', {}).get('sha') == self.state['e1']
                and existing.get('title') == TITLE and existing.get('body') == body):
            self.finish_pr(existing, body)
            return
        require(existing is None or existing.get('head', {}).get('sha') == self.state['e1'],
                'same-head draft did not observe pushed E1')
        payload = {'title': TITLE, 'body': body}
        if existing is None:
            payload.update(head=BRANCH, base=PR_BASE, draft=True, maintainer_can_modify=True)
            kind, endpoint, method = 'create-pr', f'repos/{REPOSITORY}/pulls', 'POST'
        else:
            kind, endpoint, method = 'update-pr', f'repos/{REPOSITORY}/pulls/{existing["number"]}', 'PATCH'
        payload_path = self.out / ('pull-request-' + str(len(self.commands) + 1) + '.json')
        write_new(payload_path, encoded(payload))
        write_new(payload_path.with_suffix('.body.txt'), body.encode())
        self.github_identity()
        self.run('api-write-preflight', ['bash', 'scripts/project-preflight.sh'])
        self.working_guard()
        require(self.remote_tip() == self.state['e1'], 'published branch moved before PR write')
        self.state.update(phase='publication_unknown', pending_write={'kind': kind, 'endpoint': endpoint,
            'payload': payload_path.name, 'payload_sha256': sha(encoded(payload)), 'body_sha256': sha(body.encode())})
        self.save()
        self.run('rest-draft-pull-request', ['gh', 'api', '--method', method, endpoint, '--input', str(payload_path)], required=False)
        self.finish_pr(self.find_pr(), body)

    def summary(self):
        result = {'schema': 'pon-followthrough-merged-publication-summary-v3', 'phase': self.state['phase'],
            'local_evidence_complete': self.state.get('validation_runs', [{}])[-1].get('complete', False),
            'published': self.state['phase'] == 'published', 'original_native_checkpoint': C2,
            'failed_binding_child_c3': C3, 'merged_source_m1': M1, 'merged_tree': M1_TREE,
            'evidence_child_e1': self.state.get('e1'), 'draft_pull_request': self.state.get('pull_request'),
            'pending_write': self.state.get('pending_write'),
            'publication_base_observation': self.state.get('publication_base_observation'),
            'latest_base_observation': self.state.get('base_observations', [None])[-1],
            'base_advanced_since_source_checkpoint': self.state.get('publication_base_observation', {}).get('base_advanced_since_source_checkpoint'),
            'evidence_member_count': len(self.state['expected_files']), 'commands_recorded': len(self.commands),
            'm1_required_checks_passed': self.state.get('observations', {}).get('merged_validation', {}).get('all_required_checks_passed', False),
            'c3_required_checks_passed': False, 'c3_nonzero_checks': 4, 'c3_native_child_executed': False,
            'm1_full_node_suite_executed': False, 'm1_full_node_suite_passed': False,
            'native_full_suite_passed': False, 'parent_test_results_inherited': False,
            'all_baseline_tests_passed': False, 'baseline_full_library_suite_passed': None,
            'old_v2_publisher_completion_path_invoked': False, 'hosted_ci_observed_complete': False,
            'draft_only': True, 'open_consensus_qualified': False, 'production_activation': False,
            'security_status': 'HOLD'}
        atomic_json(self.out / 'summary.json', result)
        return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('prepare', 'commit', 'validate', 'all-local', 'publish'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inputs-root', type=Path, required=True)
    parser.add_argument('--validation-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--merge-output', type=Path)
    parser.add_argument('--merge-inputs', type=Path)
    parser.add_argument('--prior-publisher', type=Path)
    parser.add_argument('--validator', type=Path)
    parser.add_argument('--baseline-output', type=Path,
                        default=Path('/home/qian-qi/chain-pon-baseline-control-20261110-685a-output'))
    parser.add_argument('--baseline-followup-output', type=Path,
                        default=Path('/home/qian-qi/chain-pon-baseline-control-20261110-685a-output-02'))
    parser.add_argument('--baseline-runner', type=Path,
                        default=Path('/home/qian-qi/chain-pon-baseline-control-20261110-685a-runner.py'))
    parser.add_argument('--baseline-followup-runner', type=Path,
                        default=Path('/home/qian-qi/chain-pon-baseline-control-20261110-685a-runner-v2.py'))
    return parser.parse_args()


def main():
    args = arguments()
    owner = None
    def interrupted(signum, frame):
        raise InterruptedError('publication recorder received signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        owner = Publisher.__new__(Publisher)
        owner.__init__(args)
        if args.phase in ('prepare', 'all-local'):
            owner.prepare()
        if args.phase in ('commit', 'all-local'):
            owner.commit()
        if args.phase in ('validate', 'all-local'):
            owner.validate()
        if args.phase == 'publish':
            owner.publish()
        print(json.dumps(owner.summary(), sort_keys=True), flush=True)
        return 0
    except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError,
            subprocess.SubprocessError, InterruptedError) as error:
        failure = {'schema': 'pon-followthrough-merged-publication-failure-v3', 'reason': str(error),
            'phase_requested': args.phase, 'recorded_unix_ns': time.time_ns(),
            'no_automatic_rollback': True, 'no_blind_remote_write_replay': True,
            'native_full_suite_passed': False, 'open_consensus_qualified': False,
            'production_activation': False, 'security_status': 'HOLD'}
        if owner is not None and getattr(owner, 'owns_output', False):
            failure.update(phase=owner.state.get('phase'), pending_write=owner.state.get('pending_write'))
            write_new(owner.out / ('failure-' + str(failure['recorded_unix_ns']) + '.json'), encoded(failure))
            atomic_json(owner.out / 'failure.json', failure)
            owner.status(args.phase, 'failed', 2)
        print(json.dumps(failure, sort_keys=True), file=sys.stderr, flush=True)
        return 2
    finally:
        if owner is not None and getattr(owner, 'owns_output', False):
            os.close(owner.lock)


if __name__ == '__main__':
    raise SystemExit(main())



