#!/usr/bin/env python3
"""Read completed original records only after the coordinating owner's TERMINAL notice.

This evidence packager never invokes Cargo, a native executable, a Git command, or
a network operation. It never reads target files. Its only writes are new files
in its own scratch directory. The prior PENDING package remains immutable.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

BASE = Path('/workspace/scratch/b5a148b09b11/next-validation')
OUT = Path(__file__).resolve().parent
RUN = BASE / 'full-node-fixture-diagnostics'
BUILD = BASE / 'composed-fixture-diagnostics-build'
PRE = BASE / 'fixture-composed-prepublish-stage'
COMMIT = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
TREE = '30f59a8ec2abdc269bf91e228c58206b23add43d'
GATE = BASE / 'final-publication' / ('committed-check-' + COMMIT)
MANIFEST = '545222b5d1baa03ca3403375170c30416b8351fdc570e5d994603c3fb2fcaa82'
ELF = '34bd6631d69e093be42a35e89ce3d989d60f7cee4f7eb75d1c0f0527c43d7acf'
PLAN = 'c85222711cb8ef0a65c11a828d8471cfc6f7faa7bd9b9a6228f745530171e27d'
REGISTRY = 'a735a2ba81243f738e9566090a6c28ebffb09f591c0e4e97fb3de6bcc51881ca'
DRIVER = 'ef0370d03e5d18758502d6bb56d9de7de77ece56c066ad8ab97a91a052a635b9'
ADDITIONS = {
    'ingress::public_v3::request_observation::tests::error_diagnostics_preserve_typed_identity_origin_and_bounded_utf8',
    'ingress::public_v3::request_observation::tests::dispatch_diagnostic_survives_distinct_terminal_cancellation_without_changing_codes',
    'ingress::public_v3::request_observation::tests::error_diagnostic_contention_does_not_block_or_reclassify_rejection',
}
NAME = re.compile(r'[A-Za-z0-9_:]+')
TERMINAL = re.compile(
    r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
    r'0 measured; 0 filtered out; finished in ([0-9]+(?:\.[0-9]+)?)s$')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def read_stable(path):
    path = Path(path)
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    require(identity(before) == identity(after) and len(raw) == after.st_size,
            'Input changed while being read: ' + str(path))
    return raw


def parse_native_log(raw, registered, ignored, actual_exit):
    """Independently read the final libtest aggregate, not nested child summaries."""
    text = raw.decode('utf-8')
    lines = text.rstrip().splitlines()
    require(bool(lines), 'Empty native log')
    terminal = TERMINAL.fullmatch(lines[-1])
    require(terminal is not None, 'Missing exact libtest terminal summary at EOF')
    status, pass_n, fail_n, ignore_n, seconds = terminal.groups()
    pass_n, fail_n, ignore_n = map(int, (pass_n, fail_n, ignore_n))
    # --show-output emits a final successes name list, after all success output.
    success_header = max((i for i, line in enumerate(lines[:-1])
                          if line == 'successes:'), default=-1)
    require(success_header >= 0, 'Missing final successes list')
    passed = []
    for line in lines[success_header + 1:]:
        if not line:
            continue
        if line.startswith('    ') and NAME.fullmatch(line[4:]):
            passed.append(line[4:])
        else:
            break
    failed = []
    if fail_n:
        failure_header = max((i for i, line in enumerate(lines[:-1])
                              if line == 'failures:'), default=-1)
        require(failure_header > success_header, 'Missing final failures list')
        for line in lines[failure_header + 1:-1]:
            if not line:
                continue
            require(line.startswith('    ') and NAME.fullmatch(line[4:]),
                    'Unexpected line in final failed-name list')
            failed.append(line[4:])
    observed_ignored = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ignored(?:,.*)?$', text, re.M)
    groups = (passed, failed, observed_ignored)
    for label, names in zip(('passed', 'failed', 'ignored'), groups):
        require(len(names) == len(set(names)), 'Duplicate ' + label + ' selector')
    counts = tuple(map(len, groups))
    require(counts == (pass_n, fail_n, ignore_n), 'Final counts do not match actual named lists')
    all_names = passed + failed + observed_ignored
    require(len(all_names) == len(set(all_names)), 'Overlapping status name sets')
    require(set(all_names) == set(registered), 'Incomplete or extra registered selectors')
    require(set(observed_ignored) == set(ignored), 'Original ignored set changed')
    require(status == ('FAILED' if failed else 'ok'), 'Summary status contradicts named failures')
    require(actual_exit == (101 if failed else 0), 'Actual native exit contradicts terminal outcome')
    return dict(passed=pass_n, failed=fail_n, ignored=ignore_n,
                passed_selectors=passed, failed_selectors=failed,
                ignored_selectors=observed_ignored, native_summary=lines[-1],
                libtest_seconds=seconds, complete_disjoint_registry=True)


def validate_registry(plan, original):
    registered, ignored = plan['registered'], plan['original_ignored']
    require(len(registered) == len(set(registered)) == 974, 'Expected exact 974 unique names')
    require(len(original['registered']) == len(set(original['registered'])) == 971,
            'Original registry is not exact 971')
    require(set(plan['candidate_additions']) == ADDITIONS, 'New selector identities changed')
    require(set(original['registered']).isdisjoint(ADDITIONS), 'New names overlap original registry')
    require(set(registered) == set(original['registered']) | ADDITIONS,
            '974 is not original 971 plus the three diagnostic tests')
    require(len(ignored) == len(set(ignored)) == 23 and
            set(ignored) == set(original['original_ignored']), 'Original 23 ignored names changed')
    require(set(ignored).issubset(registered), 'Ignored selector outside registry')
    return registered, ignored


def new_file(name, raw):
    with (OUT / name).open('xb') as target:
        target.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-terminal-notice', required=True, type=Path)
    args = parser.parse_args()
    notice_raw = read_stable(args.owner_terminal_notice)
    notice = json.loads(notice_raw)
    require(notice.get('terminal_confirmed') is True and notice.get('session_id') == 82056
            and notice.get('candidate_commit') == COMMIT,
            'Explicit root TERMINAL notice for this source/session is required')
    require(not (OUT / 'terminal-summary.json').exists(), 'Terminal stage already packaged')
    records = {}
    originals = {}

    def collect(name, path, expected=None):
        raw = read_stable(path)
        require(name not in records, 'Duplicate record path')
        if expected:
            require(sha(raw) == expected, 'Frozen identity mismatch: ' + name)
        records[name] = raw
        originals[name] = str(path)
        return json.loads(raw) if name.endswith('.json') else raw

    # Read terminal receipts before opening native.log; no polling or partial run inference.
    collect('owner-terminal-notice.json', args.owner_terminal_notice)
    terminal = collect('build/terminal.json', BUILD / 'terminal.json')
    require(terminal['native_source_unchanged'] is True, 'Terminal source change reported')
    manifest = collect('build/native-source.terminal.json', BUILD / 'native-source.terminal.json', MANIFEST)
    require(len(manifest) == 1190, 'Unexpected native manifest path count')
    for name in ('before', 'after', 'final'):
        collect('build/native-source.' + name + '.json', BUILD / ('native-source.' + name + '.json'), MANIFEST)
    plan = collect('full-registry/plan.json', RUN / 'plan.json', PLAN)
    original = collect('registry-reference/original971-plan.json', BASE / 'final-composed/full-node/plan.json', REGISTRY)
    registered, ignored = validate_registry(plan, original)
    require(plan['native_source_manifest_sha256'] == MANIFEST and plan['binary_sha256'] == ELF,
            'Plan source/ELF differs from this fixture-composed run')
    require(plan['base'] == '8ebded733d90bf74e7d8e3adbd2458ad8b572159'
            and plan['command'][1:] == ['--show-output', '--test-threads=1']
            and plan['original_registry_count'] == 971, 'Original invocation identity changed')
    require(plan['supervisor_seconds'] == 2700 and plan['native_budgets_changed'] is False,
            'Original supervisor/native budget declaration changed')
    collect('drivers/full-node.py', BASE / 'final-full-node-fixture-diagnostics.py', DRIVER)
    require(plan['reader_driver_sha256'] == DRIVER and plan['frozen_registry_plan_sha256'] == REGISTRY,
            'Original driver/reference plan binding changed')
    collect('drivers/build.py', BASE / 'composed-fixture-diagnostics-build-driver.py')
    result = collect('full-registry/result.json', RUN / 'result.json')
    require(result['timed_out'] is False and result['reader_error'] is None,
            'Actual run timed out or its original result reader failed')
    require(result['binary_sha256'] == ELF and result['binary_unchanged'] is True,
            'Actual native ELF identity changed')
    require(result['command'] == plan['command'] and result['registered_count'] == 974,
            'Actual native command/denominator mismatch')
    raw_log = collect('full-registry/native.log', RUN / 'native.log', result['log_sha256'])
    readback = parse_native_log(raw_log, registered, ignored, result['exit_code'])
    require(result['complete_original_registry'] is True, 'Original reader did not verify registry')
    for key in ('passed', 'failed', 'ignored'):
        require(result[key] == readback[key], 'Independent count disagrees: ' + key)
        require(set(result[key + '_selectors']) == set(readback[key + '_selectors']),
                'Independent names disagree: ' + key)
    artifacts = collect('build/artifacts.json', BUILD / 'artifacts.json')
    node = [x for x in artifacts if x['target']['name'] == 'trnm_pon_node' and x['target']['kind'] == ['lib']]
    require(len(node) == 1 and node[0]['sha256'] == ELF and node[0]['executable'] == plan['command'][0],
            'Cargo-produced Node artifact does not match actual native command')
    require(node[0]['profile'] == dict(opt_level='3', debuginfo=2, debug_assertions=True,
                                     overflow_checks=True, test=True), 'Original Cargo test profile changed')
    for name in ('invocation', 'result', 'build', 'fmt', 'clippy', 'verification'):
        collect('build/' + name + '.json', BUILD / (name + '.json'))
    pre_summary = collect('prepublish-reference/source-bound-summary.json', PRE / 'source-bound-summary.json',
                          'a3f0afdf1d4e9219590f10ca875063b33fd44f023d84f72ad8eb948dfa9346ee')
    require(pre_summary['full_registry']['status'] == 'PENDING', 'Original PENDING snapshot was rewritten')
    require(pre_summary['source']['native_manifest_sha256'] == MANIFEST and
            pre_summary['source']['node_elf_sha256'] == ELF, 'Prepublish source binding differs')
    collect('prepublish-reference/artifact-index.json', PRE / 'artifact-index.json',
            '03732abd2709fb1a8e1d44837cfb78d775ca6de8f5a1d60b5d1e3c9cd4477c25')

    # This is source-byte association, not a new clean-commit native execution.
    gate = collect('exact-commit/summary.json', GATE / 'summary.json')
    require(gate['status'] == 'PASS' and gate['error'] is None and gate['expected_commit'] == COMMIT,
            'Exact commit gate is not a completed PASS for the supplied commit')
    require(gate['native_compilation_executed'] is False and gate['native_tests_executed'] is False,
            'Exact-commit gate scope differs')
    source_records = []
    parity_records = []
    for position in ('before', 'after'):
        source = collect('exact-commit/source-' + position + '.json', GATE / ('source-' + position + '.json'))
        parity = collect('exact-commit/compiled-native-parity-' + position + '.json',
                         GATE / ('compiled-native-parity-' + position + '.json'))
        require(source['head'] == COMMIT and source['tree'] == TREE and source['status'] == ''
                and source['detached'] is True, 'Exact committed source was not clean and stable')
        require(parity['native_manifest_sha256'] == MANIFEST and parity['paths'] == 1190
                and parity['matched'] is True and parity['mismatches'] == [], 'Exact committed native byte parity failed')
        require(source == gate['source_' + position], 'Exact gate summary/source receipt disagrees')
        prefix = 'exact-source-' + position
        exact_receipt = collect('exact-commit/' + prefix + '.json', GATE / (prefix + '.json'))
        exact_raw = collect('exact-commit/' + prefix + '.stdout', GATE / (prefix + '.stdout'),
                            exact_receipt['stdout_sha256'])
        collect('exact-commit/' + prefix + '.stderr', GATE / (prefix + '.stderr'),
                exact_receipt['stderr_sha256'])
        exact_source = json.loads(exact_raw)
        require(exact_receipt['exit_code'] == 0 and exact_receipt['timed_out'] is False
                and exact_receipt['launch_error'] is None
                and exact_receipt['expected_commit'] == COMMIT,
                'Exact source verification command did not complete successfully')
        require(exact_source['tested_commit'] == COMMIT and exact_source['tested_tree'] == TREE
                and exact_source['tracked_worktree_verified'] is True
                and exact_source['tests_executed_by_identity_check'] is False,
                'Exact source output identity/scope disagrees')
        source_records.append(source)
        parity_records.append(parity)
    require(source_records[0] == source_records[1], 'Exact gate source before/after changed')
    require(records['exact-commit/exact-source-before.stdout'] ==
            records['exact-commit/exact-source-after.stdout'], 'Exact source output changed')
    collect('exact-commit/results.json', GATE / 'results.json')
    collect('exact-commit/invocation.json', GATE / 'invocation.json')
    association = {
        'schema': 'trnm-exact-commit-native-byte-association-v1',
        'commit': COMMIT, 'tree': TREE, 'native_manifest_sha256': MANIFEST,
        'native_paths': 1190, 'node_elf_sha256': ELF,
        'native_execution_invocation_base': plan['base'],
        'native_executed_after_clean_commit_checkout': False,
        'exact_commit_gate_native_execution': False,
        'association': 'The original Cargo build and native invocation used the frozen 1190 native bytes. The clean c5dd exact-commit gate verified those bytes while the full native run was still in progress; the native terminal manifest matched the same bytes again after completion. No full native run was launched or repeated from the clean c5dd checkout.',
        'exact_commit_gate_finished_utc': gate['finished_utc'],
        'native_driver_terminal_completed_utc': terminal['completed_utc'],
        'hosted_ci_result_inherited': False,
    }
    # Re-read all completed originals to refuse a mid-package mutation.
    for name, path in originals.items():
        require(read_stable(path) == records[name], 'Input changed after collection: ' + name)
    native_gz = gzip.compress(raw_log, compresslevel=9, mtime=0)
    require(gzip.decompress(native_gz) == raw_log and native_gz[4:8] == b'\0' * 4,
            'Native lossless gzip verification failed')
    del records['full-registry/native.log']
    entries = []
    blobs = {}
    for name, raw in records.items():
        key = sha(raw)
        entries.append(dict(path=name, original_path=originals[name], bytes=len(raw), sha256=key))
        blobs[key] = base64.b64encode(raw).decode('ascii')
    bundle_raw = encode(dict(schema='trnm-lossless-original-records-v1', entries=entries, blobs=blobs))
    bundle_gz = gzip.compress(bundle_raw, compresslevel=9, mtime=0)
    require(gzip.decompress(bundle_gz) == bundle_raw, 'Original record gzip verification failed')
    finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summary = {
        'schema': 'trnm-fixture-composed-terminal-summary-v1', 'packaged_utc': finished,
        'status': 'COMPLETE_NATIVE_TERMINAL_WITH_FAILURES' if readback['failed'] else 'COMPLETE_NATIVE_TERMINAL_PASS',
        'source': association, 'registered': 974, 'original_registered': 971,
        'candidate_additions': sorted(ADDITIONS), 'original_ignored_preserved': True,
        'passed': readback['passed'], 'failed': readback['failed'], 'ignored': readback['ignored'],
        'failed_selectors': readback['failed_selectors'], 'actual_native_exit_code': result['exit_code'],
        'driver_exit_code_from_owner_notice': notice.get('driver_exit_code'),
        'timed_out': result['timed_out'], 'reader_error': result['reader_error'],
        'wall_ns': result['wall_ns'], 'native_summary': readback['native_summary'],
        'original_supervisor_seconds': 2700, 'native_budgets_changed': False,
        'native_log': dict(path='native.log.gz', raw_bytes=len(raw_log), raw_sha256=sha(raw_log),
                           compressed_bytes=len(native_gz), compressed_sha256=sha(native_gz), gzip_mtime=0),
        'records_bundle': dict(path='terminal-records.json.gz', entries=len(entries), unique_blobs=len(blobs),
                               raw_bytes=len(bundle_raw), raw_sha256=sha(bundle_raw),
                               compressed_bytes=len(bundle_gz), compressed_sha256=sha(bundle_gz), gzip_mtime=0),
        'prior_diagnostics_only_result_inherited': False, 'prior_b280_result_inherited': False,
        'pending_snapshot_modified': False, 'additional_native_executions': 0,
        'ELF_files_read_or_copied_by_packager': False,
        'scope': 'This exact native-source full registry terminal only. Selected, real-Host, original 4s/F0/campaign and scientific acceptance remain separate.',
        'all_service_blockers_closed': False, 'performance_acceptance': False,
    }
    for name, data in (
        ('native.log.gz', native_gz), ('terminal-records.json.gz', bundle_gz),
        ('exact-commit-native-association.json', encode(association)),
        ('independent-native-readback.json', encode(readback)),
        ('terminal-summary.json', encode(summary)),
    ):
        new_file(name, data)
    index_names = ['native.log.gz', 'terminal-records.json.gz', 'exact-commit-native-association.json',
                   'independent-native-readback.json', 'terminal-summary.json', 'prepare_terminal.py']
    index = {name: dict(bytes=(OUT / name).stat().st_size, sha256=sha(read_stable(OUT / name)))
             for name in index_names}
    new_file('artifact-index.json', encode(dict(schema='trnm-fixture-terminal-artifacts-v1', files=index)))
    print(json.dumps({key: summary[key] for key in ('status', 'registered', 'passed', 'failed', 'ignored',
                                                  'actual_native_exit_code', 'timed_out', 'wall_ns')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
