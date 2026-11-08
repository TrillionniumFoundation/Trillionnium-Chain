#!/usr/bin/env python3
"""Retain the exact failed inventory follow-up run and make one evidence-only HOLD commit.

LOCAL PREPARATION: this file does nothing unless explicitly executed on the fixed
Desktop task checkout after inventory-source-01 has terminated with the reviewed exact failure.
No Cargo, network, CI rerun, signature/clock edits, push or activation is used.
All old evidence remains byte-identical except append-only README and index.
Original hosted failures remain failures. Oversized original files stay outside
Git with explicit size/hash/location records; no file is silently omitted.
"""
from __future__ import annotations
import argparse
import copy
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
sys.dont_write_bytecode = True

TASK = Path('/home/qian-qi/work/chain-pq-authority-20261108-9d315')
REPO = TASK / 'repo'
EV_REL = 'evidence/pq-authority-preflight-20261108-9d315'
EV = REPO / EV_REL
BASE = '12e510b211110d93d9ead07e02c07a1eecc28ae9'
BASE_TREE = 'a8c9634b9e0d59ccc9fd6a03875eee7fc76c099f'
UPSTREAM = '8d8f05566b2a1612a3bf4a6c6c71635df454d397'
BRANCH = 'fix/chain-pq-authority-preflight-20261108-9d315'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
LOCK_NAME = re.compile(r'\.hepta-lock-[0-9a-f]{24}')
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')
LIBTEST_SUMMARY = re.compile(
    r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; '
    r'(\d+) measured; (\d+) filtered out;.*$', re.M)
LIBTEST_NAME = re.compile(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored(?:,.*)?)$', re.M)
PROVIDER_ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
PROVIDER = PROVIDER_ROOT / 'build-runtime/trnm-pq-provider-3.5.9.DYf2qEaX/install'
PROVIDER_FILES = {
    'bin/openssl': (8933408, '8ff7dd91270fd4a8fc377031f0fd2f2cee1cd17a32ce30e4fd773a25730a120f'),
    'include/openssl/opensslv.h': (3449, '9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda'),
    'include/openssl/configuration.h': (4729, '406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996'),
    'lib/libcrypto.a': (12381776, 'dabf2189afd2e29591c5b597ac2cb9b7cd7066eaf7ce674106123614da32eb0f'),
    'lib/libssl.a': (2123138, 'f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727'),
}
OUT = TASK / 'validation/final-evidence-collection-02'
PUBLISHED = '527e2e58db6d7c1fd84ba88c3131289edea86b1d'
PUBLISHED_TREE = '21cf0f5bcccd9093397f14bbea44311b577554c0'
FIXED_SOURCE = 'ca3c4f88afc70399000b18fc7d68cfa62e57fb2f'
FIXED_TREE = 'c06c28dbbb16bb30a4f568408913313ab533c47e'
RUNNER = 'authority-final-validation-runner.py'
RUNNER_SHA256 = 'd81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710'
FIX_DIRECTORY = 'distributed-inventory-fix-01'
FIX_DRIVER_SHA256 = 'fdc884ba8f0f117b51ed3173665e4af97e358abe1519ee8edd5d29376d458162'
FIX_RECEIPT_SHA256 = '1a499c4cf604741546652750860fc1ace61f256cdb94d6143e0a90254ad906bf'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
REFRESH = 'scripts/refresh_distributed_source_inventory.py'
REFRESH_SHA256 = 'c83d9c0b84c21beec6917a86b2a3207c5f3bf6fd26cf432f2ef0990750e16a33'
MISSING = 'trillionnium/crates/trnm-release-bundle/src/pq_release/quorum_preflight_tests.rs'
REPORT = 'docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
CHANGED = sorted([INVENTORY, REPORT, PLAN, CORPUS, EV_REL + '/' + RUNNER, EV_REL + '/artifact-index.json'])
FIX_LABELS = ('preflight-before-edit', 'inventory-before-check', 'refresh-inventory',
              'inventory-after-check', 'ci-contract', 'pq-integration', 'stage-reviewed-paths',
              'staged-diff-check', 'preflight-before-commit', 'commit-inventory-fix')
REQUIRED_HOSTED = ('hosted-ci-observation-01', 'hosted-ci-native-triage-01',
                   'hosted-ci-contract-triage-01', 'hosted-ci-pr-note-01', 'hosted-ci-final-readback-01',
                   'hosted-ci-w1-triage-01', 'hosted-ci-late-priority-triage-01',
                   'hosted-ci-late-factorial-triage-01', 'hosted-ci-late-export-triage-01')
GIT_FILE_LIMIT = 100_000_000
ENV = {key: value for key, value in os.environ.items()
       if not key.startswith('GIT_') and key not in ('GH_DEBUG', 'GH_TRACE', 'GH_FORCE_TTY')}
ENV.update(GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0',
           PYTHONDONTWRITEBYTECODE='1', LANG='C.UTF-8', LC_ALL='C.UTF-8', TZ='UTC')
CREATED_OUT = False
FAILED_NODE_TESTS = (
    'release_owner::service_tests::clock_reply_then_real_elapsed_expiry_refuses_without_cas',
    'release_owner::service_tests::durable_preparation_then_real_elapsed_expiry_refuses_without_cas',
)
NODE_RECEIPT = {'bytes': 1196, 'sha256': '1fcf1afa9c1648b66513b67ee5b20d1aee57c52aea937e5a92e4c2eeb386681c'}
NODE_STDOUT = {'bytes': 10038, 'sha256': '02757b591bbbfd7daaaf455cb19794a32f8691fae50a48a36d085749cfb15256'}
NODE_STDERR = {'bytes': 399, 'sha256': '7fd459fc59c25f08d6e7d50138533d97a29d86985e230d68e4a1c7ce1ccc5d15'}
UNEXECUTED_DRAFT_SHA256 = 'd540116532977cdf3aa7cf14480bc3968cd934e2eb28978fd3ad9f60f9cce0f7'
READERS = (
    ('preflight', 'preflight'), ('source-guard-before', 'source'),
    ('distributed-source-inventory', 'exit'),
    ('rustc-version', 'rustc'), ('cargo-version', 'cargo'),
    ('openssl-version', 'openssl'), ('metadata-default', 'metadata-main'),
    ('metadata-all-features', 'metadata-main'), ('metadata-fuzz', 'metadata-fuzz'),
    ('formatting', 'exit'), ('release-non-test-library', 'exit'),
    ('release-all-targets', 'release-tests'), ('five-package-all-targets', 'rust-tests'),
    ('six-package-doc-tests', 'rust-docs'), ('node-release-owner', 'node-tests'),
    ('workspace-strict-clippy', 'exit'), ('ci-contract', 'json'),
    ('ci-contract-negatives', 'unittest'), ('upstream-migration-signatures', 'unittest'),
    ('upstream-migration-journal', 'unittest'), ('upstream-public-seed-relation', 'unittest'),
    ('pq-root-quorum-research', 'unittest'), ('pq-integration', 'hold-no-go'),
    ('pq-integration-negatives', 'unittest'), ('pq-claim', 'hold'),
    ('pq-claim-negatives', 'unittest'), ('pq-authority', 'authority-hold'),
    ('pq-authority-negatives', 'unittest'), ('source-integrity-negatives', 'unittest'),
    ('canonical-plan', 'exit'), ('repository-links', 'repository'),
    ('source-guard-after', 'source'),
)


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def record(data: bytes) -> dict:
    return {'bytes': len(data), 'sha256': sha256(data)}


def relative(value: str) -> str:
    require(isinstance(value, str) and value and '\\' not in value
            and ':' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value),
            'unsafe relative evidence path')
    path = PurePosixPath(value)
    require(path.parts and not path.is_absolute() and path.as_posix() == value
            and all(part not in ('', '.', '..') for part in path.parts), 'noncanonical evidence path: ' + value)
    return value


def read_bytes(path: Path, *, single_link: bool = True) -> bytes:
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and (not single_link or st.st_nlink == 1),
            'not a regular independent file: ' + str(path))
    require(path.resolve() == path, 'noncanonical or symlinked file: ' + str(path))
    return path.read_bytes()


def load(path: Path) -> object:
    def unique_pairs(pairs):
        value = {}
        for key, entry in pairs:
            require(key not in value, 'duplicate JSON key in ' + str(path) + ': ' + key)
            value[key] = entry
        return value
    return json.loads(read_bytes(path), object_pairs_hook=unique_pairs)


def save(path: Path, value: object, *, fresh: bool = False) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb' if fresh else 'wb') as stream:
        stream.write(data)


def check_record(data: bytes, expected: dict, label: str) -> None:
    require(isinstance(expected, dict) and type(expected.get('bytes')) is int
            and expected['bytes'] >= 0 and isinstance(expected.get('sha256'), str)
            and HEX64.fullmatch(expected['sha256']) is not None, 'malformed byte record: ' + label)
    require(record(data) == {'bytes': expected['bytes'], 'sha256': expected['sha256']},
            'byte identity mismatch: ' + label)


def git(*argv: str) -> bytes:
    return subprocess.check_output(['/usr/bin/git', '-c', 'core.quotePath=false',
                                    '-C', str(REPO), *argv], env=ENV, stderr=subprocess.PIPE)


def clean_head(expected_head: str) -> str:
    require(git('rev-parse', 'HEAD').decode().strip() == expected_head, 'HEAD differs from expected source')
    require(git('branch', '--show-current').decode().strip() == BRANCH, 'unexpected branch')
    require(not git('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none'),
            'checkout is not clean')
    entries = git('ls-files', '-v', '-z').split(b'\0')
    require(all(not row or row[:1] == b'H' for row in entries), 'nonordinary tracked-file flags')
    return git('rev-parse', 'HEAD^{tree}').decode().strip()


class Capture:
    def __init__(self):
        self.rows = []

    def run(self, label: str, argv: list[str], *, allowed: tuple[int, ...] = (0,)):
        require(label not in {row['label'] for row in self.rows}, 'duplicate collection command label')
        start = time.monotonic()
        result = subprocess.run(argv, cwd=REPO, env=ENV, capture_output=True)
        logs = {}
        for stream, data in (('stdout', result.stdout), ('stderr', result.stderr)):
            name = label + '.' + stream + '.log'
            with (OUT / name).open('xb') as output:
                output.write(data)
            logs[name] = record(data)
        row = {'label': label, 'argv': argv, 'exit_code': result.returncode,
               'elapsed_seconds': time.monotonic() - start, 'logs': logs}
        self.rows.append(row)
        save(OUT / 'commands.json', self.rows)
        print(json.dumps({'step': label, 'exit_code': result.returncode}), flush=True)
        require(result.returncode in allowed, 'collection command failed: ' + label)
        return result


def validate_raw_log_record(directory: Path, name: str, expected: dict) -> bytes:
    relative(name)
    require('/' not in name, 'receipt log is not a direct child')
    data = read_bytes(directory / name)
    check_record(data, expected, str(directory / name))
    if 'path' in expected:
        require(expected['path'] == str(directory / name), 'raw log receipt path differs')
    return data


def parse_counts(row: dict, stdout: bytes, stderr: bytes, reader: str) -> dict | None:
    text = stdout.decode('utf-8', errors='replace')
    if reader == 'unittest':
        combined = text + '\n' + stderr.decode('utf-8', errors='replace')
        counts = [int(n) for n in re.findall(r'^Ran (\d+) tests? in .+$', combined, re.M)]
        require(counts and counts[-1] > 0 and re.search(r'^OK(?: \(.*\))?$', combined, re.M),
                'missing successful Python readback: ' + row['label'])
        require(row.get('readback') == {'reported_test_counts': counts}, 'Python receipt/raw mismatch')
        return {'tests': counts[-1], 'reported_test_counts': counts}
    if reader in ('release-tests', 'rust-tests', 'rust-docs', 'node-tests'):
        summaries = [list(map(int, item)) for item in LIBTEST_SUMMARY.findall(text)]
        names = LIBTEST_NAME.findall(text)
        passed = [name for name, outcome in names if outcome == 'ok']
        ignored = [name for name, outcome in names if outcome.startswith('ignored')]
        require(summaries and all(values[1] == 0 for values in summaries), 'missing successful libtest readback')
        require(row.get('readback') == {'summaries': summaries, 'passed_names': passed,
                                      'ignored_names': ignored}, 'native receipt/raw mismatch')
        totals = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered'),
                          (sum(values[i] for values in summaries) for i in range(5))))
        require(totals['passed'] > 0, 'empty native scope')
        return {**totals, 'summaries': summaries, 'passed_names': passed, 'ignored_names': ignored}
    return None


def failed_node_counts(stdout: bytes, stderr: bytes) -> dict:
    check_record(stdout, NODE_STDOUT, 'independently observed Node stdout')
    check_record(stderr, NODE_STDERR, 'independently observed Node stderr')
    text = stdout.decode()
    rows = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                      r'(\d+) measured; (\d+) filtered out;.*$', text, re.M)
    require(rows == [('FAILED', '38', '2', '1', '0', '1244')], 'Node failed libtest summary differs')
    names = LIBTEST_NAME.findall(text)
    passed = [name for name, outcome in names if outcome == 'ok']
    failed = [name for name, outcome in names if outcome == 'FAILED']
    ignored = [name for name, outcome in names if outcome.startswith('ignored')]
    require(len(names) == len({name for name, _ in names}) == 41
            and len(passed) == 38 and len(ignored) == 1 and failed == list(FAILED_NODE_TESTS)
            and all(name.startswith('release_owner::') for name, _ in names),
            'Node failure is not the exact independently observed two-test failure')
    require('service_test_fixture.rs:215:51:' in text
            and 'called `Result::unwrap()` on an `Err` value: Kind(TimedOut)' in text
            and 'service_tests.rs:87:9:' in text
            and '  left: TimedOut\n right: PermissionDenied' in text,
            'actual Node failure diagnostics differ')
    require('release_owner::service_tests::admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch'
            in passed, 'earlier corrected positive control did not actually pass')
    return {'result': 'FAIL', 'passed': 38, 'failed': 2, 'ignored': 1, 'measured': 0, 'filtered': 1244,
            'summaries': [[38, 2, 1, 0, 1244]], 'passed_names': passed,
            'failed_names': failed, 'ignored_names': ignored}


def validate_failed_run(expected_head: str, tree: str, directory: str, expected_summary_sha256: str) -> dict:
    source = TASK / 'validation' / directory
    require(sha256(read_bytes(source / 'summary.json')) == expected_summary_sha256,
            'terminal failed summary differs from the exact reviewed observation')
    summary = load(source / 'summary.json')
    require(summary.get('schema') == 'trnm-pq-authority-validation-v1'
            and summary.get('result') == 'FAIL' and summary.get('failures') == []
            and summary.get('expected_head') == expected_head and summary.get('repo') == str(REPO),
            'summary is not the reviewed terminal failed exact-source run')
    require(summary.get('source_unchanged') is True and summary.get('provider_unchanged') is True
            and summary.get('production_activation') is False
            and summary.get('whole_chain_quantum_security_qualified') is False, 'run source/provider/scope guard failed')
    rows = summary.get('commands')
    specs = load(source / 'commands.json')
    require(isinstance(rows, list) and len(rows) == 32
            and [(s['label'], s['reader']) for s in specs] == list(READERS)
            and [r['label'] for r in rows] == [name for name, _ in READERS], 'not the exact reviewed 32 gates')
    runner = read_bytes(source / 'authority-validation-runner.py')
    require(sha256(runner) == RUNNER_SHA256 and runner == read_bytes(EV / RUNNER),
            'retained runner differs from the committed final runner')
    check_record(runner, summary.get('runner'), 'retained final runner')
    require(summary['runner'].get('path') == str(source / 'authority-validation-runner.py'), 'runner receipt path differs')
    spec = importlib.util.spec_from_file_location('reviewed_final_validation', EV / RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    canonical = [{'label': label, 'argv': argv, 'reader': reader}
                 for label, argv, reader in module.command_list(expected_head, source)]
    require(specs == canonical, 'retained commands differ from the frozen final runner')
    native, python = {}, {}
    for spec, row, (_, reader) in zip(specs, rows, READERS):
        label = row['label']
        failed_node = label == 'node-release-owner'
        require(row.get('passed') is (not failed_node) and type(row.get('exit_code')) is int
                and row['exit_code'] == (101 if failed_node else 0) and not row.get('timed_out')
                and not row.get('blocked') and not row.get('error')
                and row.get('argv') == spec['argv'] and row.get('cwd') == str(REPO),
                'gate differs from the exact 31-pass/one-failed-command observation: ' + label)
        require(load(source / (label + '.receipt.json')) == row, 'summary/individual receipt differs: ' + label)
        names = [label + '.stdout.log', label + '.stderr.log']
        require(set(row.get('logs', {})) == set(names), 'gate did not retain both output streams')
        stdout, stderr = [validate_raw_log_record(source, name, row['logs'][name]) for name in names]
        if failed_node:
            require('readback' not in row and 'error' not in row, 'failed Node receipt was rewritten')
            require(file_record(source / (label + '.receipt.json')) == NODE_RECEIPT,
                    'failed Node receipt differs from the independently read original')
            counts = failed_node_counts(stdout, stderr)
            try:
                module.validate_output(reader, stdout.decode(), stderr.decode(), REPO)
            except ValueError:
                pass
            else:
                raise EvidenceError('the frozen success reader unexpectedly admitted the failed Node output')
        else:
            actual_readback = module.validate_output(reader, stdout.decode(errors='replace'),
                                                     stderr.decode(errors='replace'), REPO)
            require(json.loads(json.dumps(actual_readback)) == row.get('readback'),
                    'frozen reader disagrees with actual retained output: ' + label)
            counts = parse_counts(row, stdout, stderr, reader)
        if reader == 'unittest':
            python[label] = counts
        elif counts is not None:
            native[label] = counts
        if reader in ('preflight', 'json', 'hold-no-go', 'hold', 'authority-hold', 'repository'):
            value = json.loads(stdout)
            require(value == row.get('readback'), 'JSON receipt/raw mismatch: ' + label)
            if reader in ('preflight', 'repository'):
                require(value.get('result') == 'PASS', 'non-PASS source admission')
            if reader == 'hold-no-go':
                require(value.get('status') == 'HOLD_NO_GO' and value.get('cryptographic_acceptance') is False
                        and value.get('node_activated') is False, 'PQ source scope changed')
            if reader == 'hold':
                require(value.get('status') == 'HOLD' and value.get('whole_chain_pq_qualified') is False,
                        'whole-chain claim must remain held')
            if reader == 'authority-hold':
                require(value.get('status') == 'HOLD_INCOMPLETE_AUTHORITY_TRACING', 'authority scope changed')
            if reader == 'repository':
                require(value.get('runtime_implemented') is False and value.get('activation') is False,
                        'repository scope changed')
        if reader == 'source':
            require('--expected-head' in row['argv']
                    and row['argv'][row['argv'].index('--expected-head') + 1] == expected_head,
                    'raw source guard used the wrong commit')
    for label, expected in {'ci-contract-negatives': 116, 'pq-root-quorum-research': 18,
                            'upstream-migration-signatures': 7, 'upstream-migration-journal': 13,
                            'upstream-public-seed-relation': 21}.items():
        require(python[label]['tests'] == expected, 'reviewed Python count differs: ' + label)
    expected_native = {'release-all-targets': (52, 0, 0), 'five-package-all-targets': (442, 2, 0),
                       'six-package-doc-tests': (4, 0, 0), 'node-release-owner': (38, 1, 1244)}
    for label, expected in expected_native.items():
        values = native[label]
        require((values['passed'], values['ignored'], values['filtered']) == expected
                and values['failed'] == (2 if label == 'node-release-owner' else 0)
                and values['measured'] == 0, 'reviewed native scope differs: ' + label)
    roster = load(REPO / 'config/pon/pq-initial-root-material-required-tests-v1.json')
    expected_names = roster['complete_release_tests']
    release_names = native['release-all-targets']['passed_names']
    require(roster['expected_controls'] == {'original_release': 37, 'initial_root_material': 6,
                                          'quorum_preflight': 9, 'complete_release': 52}
            and len(expected_names) == len(set(expected_names)) == len(release_names) == 52
            and set(expected_names) == set(release_names), 'release execution does not match exact 52 roster')
    node = native['node-release-owner']
    require(len(node['summaries']) == 1 and len(node['passed_names']) == len(set(node['passed_names'])) == node['passed']
            and all(name.startswith('release_owner::') for name in node['passed_names'] + node['ignored_names']),
            'Node results exceed the reviewed release_owner scope')
    before, after = load(source / 'source-before.json'), load(source / 'source-after.json')
    require(before == after and before.get('head') == expected_head and before.get('tree') == tree
            and before.get('branch') == BRANCH and before.get('status') == ''
            and before.get('index_entries_sha256') == sha256(git('ls-files', '--stage', '-z')),
            'source before/after/current identity mismatch')
    for name in ('trillionnium/Cargo.lock', 'tests/fuzz/Cargo.lock'):
        expected = before['lockfiles'][name]
        require(expected.get('path') == str(REPO / name), 'lock receipt path differs')
        check_record(read_bytes(REPO / name), expected, name)
    for phase in ('before', 'after'):
        require(isinstance(load(source / ('verified-source-' + phase + '.json')), dict), 'missing raw source proof')
    provider = load(source / 'provider-before.json')
    require(provider == load(source / 'provider-after.json'), 'provider before/after identity differs')
    expected_paths = {str(PROVIDER / name): values for name, values in PROVIDER_FILES.items()}
    items = provider.get('native_inputs', [])
    require(len(items) == len(expected_paths) and
            {entry['path']: (entry['bytes'], entry['sha256']) for entry in items} == expected_paths,
            'provider input set differs from fixed 3.5.9 build')
    for key, path in (('env_file', PROVIDER_ROOT / 'build-runtime/provider.env'),
                      ('receipt', PROVIDER_ROOT / 'build-receipts/pq-provider/provider.json')):
        require(provider[key].get('path') == str(path), 'provider provenance path differs')
        check_record(read_bytes(path, single_link=False), provider[key], str(path))
    for item in items:
        check_record(read_bytes(Path(item['path']), single_link=False), item, item['path'])
    sqlite = load(source / 'sqlite-qualification.json')
    require(sqlite.get('passed') is True and sqlite.get('outputs'), 'SQLite qualification is not PASS')
    retained_sqlite = []
    for item in sqlite['outputs']:
        retained = Path(item['retained']['path'])
        require(retained.parent == source / 'sqlite-build-outputs' and item.get('qualified') is True,
                'unqualified or misplaced retained SQLite output')
        data = read_bytes(retained)
        check_record(data, item['retained'], str(retained))
        require(b'cargo:rustc-cfg=trnm_sqlite_layout_witness\n' in data
                and b'cargo:rustc-env=TRNM_SQLITE3_BUILD_FENCE=sqlite-3.51.3-normal-native-linux-layout-v3\n' in data
                and b'UNQUALIFIED:' not in data and b'TRNM_SQLITE3_UNQUALIFIED_REASON=' not in data,
                'SQLite retained markers do not qualify')
        retained_sqlite.append(retained.name)
    require(len(retained_sqlite) == len(set(retained_sqlite))
            and set(retained_sqlite) == set(inventory(source / 'sqlite-build-outputs')),
            'SQLite receipt does not cover the exact retained build-output inventory')
    return {'result': 'FAIL', 'evidence_readback': 'PASS', 'native_validation_passed': False,
            'tested_commit': expected_head, 'tested_tree': tree,
            'validation_directory': directory, 'command_gates': len(rows),
            'successful_command_gates': 31, 'failed_command_gates': ['node-release-owner'],
            'native': native, 'python': python, 'summary': record(read_bytes(source / 'summary.json')),
            'source_unchanged': True, 'provider_unchanged': True, 'sqlite_qualified': True,
            'production_activation': False, 'whole_chain_pq_qualified': False}


def outside_evidence_tree(commit: str) -> bytes:
    return b'\0'.join(row for row in git('ls-tree', '-r', '-z', commit).split(b'\0')
                      if row and not row.split(b'\t', 1)[1].startswith((EV_REL + '/').encode()))


def file_record(path: Path) -> dict:
    """Hash without loading a possibly large original artifact into memory."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and path.resolve() == path,
            'not an independent canonical regular file: ' + str(path))
    digest, count = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
            count += len(chunk)
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and count == before.st_size, 'file changed while hashing: ' + str(path))
    return {'bytes': count, 'sha256': digest.hexdigest()}


def inventory(root: Path, *, evidence: bool = False) -> dict[str, dict]:
    require(root.is_dir() and root.resolve() == root, 'invalid inventory root: ' + str(root))
    files = {}
    for path in sorted(root.rglob('*')):
        st = path.lstat()
        require(not stat.S_ISLNK(st.st_mode), 'symlink in retained tree: ' + str(path))
        if stat.S_ISDIR(st.st_mode):
            continue
        name = relative(path.relative_to(root).as_posix())
        if LOCK_NAME.fullmatch(path.name):
            require(stat.S_ISREG(st.st_mode) and st.st_size == 0, 'nonempty or unusual tool lock')
            continue
        if evidence and name == 'artifact-index.json':
            continue
        files[name] = file_record(path)
    return files


def gzip_record(path: Path) -> dict:
    digest, count = hashlib.sha256(), 0
    with gzip.open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
            count += len(chunk)
    return {'bytes': count, 'sha256': digest.hexdigest()}


def validate_index(index: dict) -> None:
    require(index.get('schema') == 'trnm-pq-authority-artifacts-v1'
            and index.get('base_commit') == BASE and index.get('base_tree') == BASE_TREE
            and index.get('concurrent_base_commit') == UPSTREAM, 'artifact index identity differs')
    require(index.get('production_activation') is False and index.get('whole_chain_pq_qualified') is False,
            'artifact index must retain its held scope')
    require(isinstance(index.get('frozen_research_source_sha256'), dict)
            and index['frozen_research_source_sha256'], 'missing frozen research identities')
    require(index.get('files') == inventory(EV, evidence=True), 'artifact index is not the exact file inventory')
    require(all(value['bytes'] < GIT_FILE_LIMIT for value in index['files'].values()),
            'an indexed file exceeds the conservative Git individual-file limit')
    require(isinstance(index.get('compression'), dict), 'missing original compression mapping')
    for name, details in index['compression'].items():
        relative(name)
        require(name.endswith('.gz') and name in index['files'], 'unindexed gzip record')
        require(index['files'][name] == {'bytes': details['compressed_bytes'],
                                       'sha256': details['compressed_sha256']}, 'stored gzip identity differs')
        raw = details['uncompressed']
        require(gzip_record(EV / name) == {key: raw[key] for key in ('bytes', 'sha256')},
                'lossless gzip identity differs: ' + name)
        if 'relative_path' in raw:
            require(relative(raw['relative_path']) != name, 'gzip maps a file to itself')


def validate_fix(expected_head: str, tree: str) -> dict:
    directory = TASK / 'validation' / FIX_DIRECTORY
    receipt = load(directory / 'receipt.json')
    require(sha256(read_bytes(directory / 'receipt.json')) == FIX_RECEIPT_SHA256,
            'completed source-fix receipt differs from the reviewed terminal result')
    require(receipt.get('schema') == 'trnm-distributed-source-inventory-fix-v1'
            and receipt.get('result') == 'PASS' and receipt.get('failures') == []
            and receipt.get('parent_commit') == PUBLISHED and receipt.get('source_commit') == expected_head
            and receipt.get('source_tree') == tree and receipt.get('changed_paths') == CHANGED,
            'source-fix admission differs')
    require(receipt.get('expected_red_label') == 'inventory-before-check'
            and receipt.get('original_31_commands_preserved') is True
            and receipt.get('declared_final_gates') == 32, 'source-fix gate history differs')
    for key in ('native_validation_executed', 'production_activation', 'whole_chain_pq_qualified',
                'hosted_ci_passed', 'native_signature_implementation_changed'):
        require(receipt.get(key) is False, 'source-fix scope changed: ' + key)
    require(sha256(read_bytes(directory / 'apply-distributed-inventory-fix.py')) == FIX_DRIVER_SHA256,
            'source-fix driver differs')
    rows = receipt.get('commands', [])
    require([row.get('label') for row in rows] == list(FIX_LABELS), 'not the exact ten source-fix commands')
    for row in rows:
        label = row['label']
        red = label == 'inventory-before-check'
        require(row.get('exit_code') == (1 if red else 0) and row.get('passed') is (not red)
                and row.get('cwd') == str(REPO) and not row.get('timed_out')
                and not row.get('error') and not row.get('blocked'), 'unexpected source-fix command outcome')
        require(load(directory / (label + '.receipt.json')) == row, 'source-fix receipt/row differs')
        names = [label + '.stdout.log', label + '.stderr.log']
        require(set(row.get('logs', {})) == set(names), 'source-fix output stream missing')
        stdout, stderr = [validate_raw_log_record(directory, name, row['logs'][name]) for name in names]
        if red:
            require(not stdout and stderr == b'distributed native source inventory differs; refresh before freezing source\n',
                    'expected red source-inventory failure differs')
        if label == 'inventory-after-check':
            require(stdout == b'distributed source inventory: PASS\n', 'fresh inventory did not report PASS')
        if label.startswith('preflight-'):
            require(json.loads(stdout).get('result') == 'PASS' and json.loads(stdout) == row['readback'],
                    'source-fix preflight did not report PASS')
        if label == 'pq-integration':
            value = json.loads(stdout)
            require(value == row['readback'] and value.get('status') == 'HOLD_NO_GO'
                    and value.get('cryptographic_acceptance') is False and value.get('node_activated') is False,
                    'source-fix integration scope differs')
    before, after = load(directory / 'source-before.json'), load(directory / 'source-after.json')
    require(before.get('head') == PUBLISHED and before.get('tree') == PUBLISHED_TREE
            and after.get('head') == expected_head and after.get('tree') == tree
            and before.get('branch') == after.get('branch') == BRANCH
            and before.get('status') == after.get('status') == '', 'source-fix identity changed')
    for name in ('trillionnium/Cargo.lock', 'tests/fuzz/Cargo.lock'):
        require(before['lockfiles'][name] == after['lockfiles'][name], 'inventory repair changed a lockfile')
        check_record(read_bytes(REPO / name), after['lockfiles'][name], name)
    inv = receipt['inventory']
    require(inv.get('path') == INVENTORY and inv.get('before_paths') == 1368 and inv.get('after_paths') == 1369
            and inv.get('added_paths') == [MISSING] and inv.get('removed_paths') == [],
            'inventory repair exceeds the one omitted path')
    for phase, commit in (('before', PUBLISHED), ('after', expected_head)):
        raw = read_bytes(directory / ('inventory-' + phase + '.raw'))
        check_record(raw, inv[phase], 'inventory ' + phase)
        require(raw == git('show', commit + ':' + INVENTORY), 'retained inventory differs from actual source')
    require(receipt['corpus']['pinned_blobs'] == 724 and receipt['corpus']['required_paths'] == 643
            and receipt['corpus']['all_eight_assertions_false'] is True
            and receipt['corpus']['new_pins'] == [EV_REL + '/' + RUNNER, REFRESH], 'source-fix corpus differs')
    require(receipt['artifact_index'] == {'before_files': 499, 'after_files': 500,
            'only_new_entry': RUNNER, 'validated_commits_unchanged': True}, 'source-fix index differs')
    check_record(read_bytes(EV / RUNNER), receipt['validation_runner'], 'final runner source-fix record')
    return {'schema': receipt['schema'], 'directory': FIX_DIRECTORY, 'result': 'PASS',
            'source_commit': expected_head, 'source_tree': tree, 'parent_commit': PUBLISHED,
            'commands': 10, 'successful_commands': 9, 'expected_failed_command':
            {'label': 'inventory-before-check', 'exit_code': 1, 'passed': False},
            'native_validation_executed': False, 'receipt': record(read_bytes(directory / 'receipt.json'))}


def hosted_directories() -> list[str]:
    paths = sorted((TASK / 'validation').glob('hosted-ci-*'))
    require(all(path.is_dir() and not path.is_symlink() and path.resolve() == path for path in paths),
            'noncanonical hosted observation directory')
    names = [relative(path.name) for path in paths]
    require(set(REQUIRED_HOSTED) <= set(names), 'a required original hosted observation is missing')
    return names


def validate_hosted_snapshot() -> dict:
    """Require the scoped observation job to be terminal; re-read its raw pages."""
    source = TASK / 'validation/hosted-ci-final-readback-01'
    value = load(source / 'receipt.json')
    require(value.get('schema') == 'trnm-hosted-ci-final-readback-v1'
            and value.get('result') == 'OBSERVED' and value.get('observed_commit') == PUBLISHED
            and value.get('source_unchanged') is True and value.get('authenticated_user') == 'ProfHepta'
            and value.get('hosted_ci_passed') is False and value.get('native_validation_executed') is False
            and value.get('production_activation') is False
            and type(value.get('finished_unix_seconds')) in (int, float)
            and value['finished_unix_seconds'] >= value['started_unix_seconds'],
            'final hosted readback is not the terminal scoped observation')
    require(value['source_before'] == value['source_after'] ==
            {'head': FIXED_SOURCE, 'tree': FIXED_TREE, 'status': ''}, 'hosted observer changed the local source')
    require(value.get('pull') == {'base': UPSTREAM, 'draft': True, 'head': PUBLISHED, 'number': 796,
            'state': 'open', 'url': 'https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/796'},
            'hosted readback observed a different PR/head/base')
    rows, pages = value.get('commands', []), []
    require(isinstance(rows, list) and len(rows) >= 3, 'hosted readback commands missing')
    for i, row in enumerate(rows):
        label = ('authenticated-user' if i == 0 else 'pull-796' if i == 1 else 'check-runs-page-' + str(i - 1))
        endpoint = ('user' if i == 0 else 'repos/TrillionniumFoundation/Trillionnium-Chain/pulls/796' if i == 1 else
                    'repos/TrillionniumFoundation/Trillionnium-Chain/commits/' + PUBLISHED
                    + '/check-runs?filter=latest&per_page=100&page=' + str(i - 1))
        require(row.get('label') == label and row.get('exit_code') == 0
                and row.get('argv') == ['/usr/bin/gh', 'api', endpoint], 'unexpected hosted readback command')
        names = [label + '.stdout.log', label + '.stderr.log']
        require(set(row.get('logs', {})) == set(names), 'hosted readback raw stream missing')
        stdout, _stderr = [validate_raw_log_record(source, name, row['logs'][name]) for name in names]
        if i >= 2:
            page = json.loads(stdout)
            require(page.get('total_count') == value.get('total_count') and isinstance(page.get('check_runs'), list),
                    'hosted paginated check count differs')
            pages.extend(page['check_runs'])
    require(len(pages) == value.get('total_count') > 0 and len({row['id'] for row in pages}) == len(pages),
            'hosted check pagination is incomplete or duplicated')
    require(all(row.get('head_sha') == PUBLISHED for row in pages), 'hosted checks belong to a different source')
    counts = dict(Counter(row.get('conclusion') if row['status'] == 'completed' else row['status'] for row in pages))
    require(counts == value.get('counts') and counts.get('failure', 0) > 0, 'raw hosted outcomes differ from receipt')
    keys = ('id', 'name', 'status', 'conclusion', 'html_url', 'started_at', 'completed_at')
    non_success = {row['id']: {key: row.get(key) for key in keys} for row in pages if row.get('conclusion') not in ('success', 'skipped')}
    require(non_success == {row['id']: row for row in value.get('non_success', [])}, 'hosted non-success records differ')
    return {'result': 'OBSERVED', 'observed_commit': PUBLISHED, 'directory': source.name,
            'finished_unix_seconds': value['finished_unix_seconds'],
            'observed_at_utc': datetime.fromtimestamp(value['finished_unix_seconds'], timezone.utc).isoformat(),
            'total_count': len(pages), 'counts': counts, 'hosted_ci_passed': False,
            'receipt': file_record(source / 'receipt.json')}


def copy_archive(name: str, external: list[dict]) -> dict:
    source, destination = TASK / 'validation' / name, EV / name
    require(not destination.exists(), 'archive scope already exists: ' + name)
    original = inventory(source)
    require(original, 'empty original archive: ' + name)
    destination.mkdir()
    copied, external_names = {}, []
    for item, expected in original.items():
        if expected['bytes'] >= GIT_FILE_LIMIT:
            external.append({'directory': name, 'relative_path': item, 'original_path': str(source / item),
                             **expected, 'included_in_git': False, 'original_preserved_outside_git': True,
                             'reason': 'individual original file is at least the conservative 100000000-byte Git limit'})
            external_names.append(item)
            continue
        target = destination / item
        target.parent.mkdir(parents=True, exist_ok=True)
        with (source / item).open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        require(file_record(target) == expected, 'archive copy differs: ' + name + '/' + item)
        copied[item] = expected
    require(inventory(source) == original, 'original directory changed while copying: ' + name)
    require(set(copied) | set(external_names) == set(original)
            and not set(copied) & set(external_names), 'archive accounting omitted an original file')
    return {'original_directory': str(source), 'original_files': original,
            'copied_original_files': copied, 'external_original_files': external_names,
            'excluded_files': 'only zero-byte tool lock files; all ordinary empty logs retained'}


def compress_new(name: str, index: dict, original: dict, protected: set[str], deleted: set[str]) -> dict:
    relative(name)
    require(name not in original['files'] and name not in ('README.md', 'artifact-index.json')
            and EV_REL + '/' + name not in protected and not name.endswith('.gz'),
            'refusing to transform old evidence or protected source: ' + name)
    source, destination = EV / name, EV / (name + '.gz')
    require(not destination.exists() and name + '.gz' not in index['compression'], 'gzip destination collision')
    before = file_record(source)
    require(before['bytes'] < GIT_FILE_LIMIT, 'oversized original must remain explicitly external')
    with source.open('rb') as src, destination.open('xb') as dst:
        with gzip.GzipFile(filename='', fileobj=dst, mode='wb', compresslevel=9, mtime=0) as zipper:
            shutil.copyfileobj(src, zipper, length=1024 * 1024)
    require(gzip_record(destination) == before and file_record(source) == before, 'gzip roundtrip changed original bytes')
    encoded = file_record(destination)
    require(encoded['bytes'] < GIT_FILE_LIMIT, 'compressed capture exceeds the Git file limit')
    details = {'compressed_bytes': encoded['bytes'], 'compressed_sha256': encoded['sha256'],
               'uncompressed': {**before, 'relative_path': name}}
    index['compression'][name + '.gz'] = details
    if git('ls-files', '-z', '--', EV_REL + '/' + name):
        deleted.add(EV_REL + '/' + name)
    source.unlink()
    return details


def preserve_original(index: dict, original: dict, old_readme: bytes) -> None:
    require(read_bytes(EV / 'README.md').startswith(old_readme), 'old README content was rewritten')
    for name, value in original['files'].items():
        if name != 'README.md':
            require(file_record(EV / name) == value, 'old evidence changed: ' + name)
    for key, value in original.items():
        if key in ('files', 'compression', 'validated_commits', 'supplementary_evidence', 'followup_evidence', 'retained_failed_validations'):
            continue
        require(index.get(key) == value, 'immutable old metadata changed: ' + key)
    for name, value in original['compression'].items():
        require(index['compression'].get(name) == value, 'old lossless mapping changed')
    for key in ('validated_commits', 'supplementary_evidence', 'followup_evidence', 'retained_failed_validations'):
        old = original.get(key, [])
        require(index.get(key, [])[:len(old)] == old, 'old metadata prefix changed: ' + key)


def rebuild_index(index: dict, original: dict, old_readme: bytes) -> None:
    preserve_original(index, original, old_readme)
    index['files'] = inventory(EV, evidence=True)
    save(EV / 'artifact-index.json', index)
    validate_index(index)


def staged_inventory(index: dict) -> None:
    entries = {}
    for row in git('ls-files', '--stage', '-z', '--', EV_REL).split(b'\0'):
        if not row:
            continue
        header, raw_path = row.split(b'\t', 1)
        mode, oid, stage = header.decode().split()
        require(stage == '0' and mode in ('100644', '100755'), 'nonregular or unmerged evidence index entry')
        entries[raw_path.decode()] = oid
    expected = {EV_REL + '/' + name: value for name, value in index['files'].items()}
    expected[EV_REL + '/artifact-index.json'] = file_record(EV / 'artifact-index.json')
    require(set(entries) == set(expected), 'staged evidence has extra or missing paths')
    child = subprocess.Popen(['/usr/bin/git', '-C', str(REPO), 'cat-file', '--batch'], env=ENV,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for path in sorted(expected):
            oid = entries[path]
            child.stdin.write((oid + '\n').encode())
            child.stdin.flush()
            header = child.stdout.readline().decode().strip().split()
            require(len(header) == 3 and header[0] == oid and header[1] == 'blob', 'invalid staged blob response')
            size = int(header[2])
            require(size == expected[path]['bytes'] and size < GIT_FILE_LIMIT, 'staged blob size differs')
            remaining, sha, git_sha = size, hashlib.sha256(), hashlib.sha1(b'blob ' + str(size).encode() + b'\0')
            while remaining:
                chunk = child.stdout.read(min(remaining, 1024 * 1024))
                require(chunk, 'truncated staged blob')
                sha.update(chunk)
                git_sha.update(chunk)
                remaining -= len(chunk)
            require(child.stdout.read(1) == b'\n' and sha.hexdigest() == expected[path]['sha256']
                    and git_sha.hexdigest() == oid, 'staged blob differs: ' + path)
        child.stdin.close()
        require(child.wait() == 0, 'staged blob reader failed')
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream and not stream.closed:
                stream.close()


def stage(index: dict, deleted: set[str], capture: Capture, number: int) -> None:
    paths = sorted({EV_REL + '/' + name for name in index['files']}
                   | {EV_REL + '/artifact-index.json'} | deleted)
    capture.run('stage-exact-inventory-' + str(number), ['/usr/bin/git', 'add', '--force', '--', *paths])
    staged_inventory(index)
    deleted.clear()


def readme_section(result: dict) -> str:
    snapshot = result['hosted_snapshot']
    counts = snapshot['counts']
    return f'''

## Inventory correction retained with local and hosted HOLD

**Current local validation is FAIL, not a 32-gate pass.** The complete run on
`{result['tested_commit']}` retained [its original summary]({result['validation_directory']}/summary.json):
31 command gates passed, while `node-release-owner` exited 101. This collector's
PASS means that the evidence was verified and retained, not that the failed
native validation became successful. The tested commit is recorded under
`retained_failed_validations`; `validated_commits` keeps its earlier identities.

The initially published source `{PUBLISHED}` omitted the new quorum test file
from the embedded distributed source inventory. This was our integration
omission. The base inventory was fresh. The unchanged generator adds only
`{MISSING}`, from 1,368 to 1,369 entries. [The separate inventory correction
record](inventory-source-correction.json) binds the exact six-file correction.
The earlier `source-correction.json`, documenting the positive Node fixture
correction, has not been rewritten. [The inventory-fix receipt]({FIX_DIRECTORY}/receipt.json)
retains one expected failed pre-fix check (exit 1, `passed: false`) and nine
successful commands; the fix driver did not run native tests.

The frozen final runner preserves the original 31 commands and adds the actual
inventory freshness command immediately after the first source guard. That
freshness check passed on the corrected source. [The original raw-output
readback](inventory-validation-readback.json) records the complete outcome:

| Scope | Actual outcome on this source |
| --- | --- |
| Release library suite | 52 passed, exact 37 + 6 + 9 names, none ignored |
| Five other related packages | 442 passed, 2 existing ignored |
| Six-package documentation tests | 4 passed |
| Node `release_owner::` module | **38 passed, 2 failed**, 1 existing ignored, 1,244 filtered |
| CI contract / pure root research | 116 / 18 passed |
| Three upstream migration groups | 7 / 13 / 21 passed |
| Other command gates | Strict workspace Clippy, formatting, three locked graphs, source guards, provider identity and SQLite qualification passed |

The two actual Node failures are:

- `release_owner::service_tests::clock_reply_then_real_elapsed_expiry_refuses_without_cas`:
  the initialized fixture's open path panicked at `service_test_fixture.rs:215:51`
  with `Kind(TimedOut)`, before the intended injected elapsed-expiry point.
- `release_owner::service_tests::durable_preparation_then_real_elapsed_expiry_refuses_without_cas`:
  the assertion at `service_tests.rs:87:9` observed `TimedOut` where the test
  required `PermissionDenied`. This is a failed test, not a successful expected
  refusal. The earlier corrected positive `admitted_completion_after_expiry...`
  control did pass in the same output.

No native or CI rerun was used to replace these outcomes, and no clock,
signature, service deadline, business threshold, or refusal assertion was
changed after this observation. The previous 31-command PASS remains bound to
its previous source; it does not establish that this newer source passed.

### Retained hosted CI failures on the earlier published source

[The scoped readback](hosted-ci-final-readback-01/receipt.json) observed
{snapshot['total_count']} checks on `{PUBLISHED}` at `{snapshot['observed_at_utc']}`:
{counts.get('success', 0)} success, {counts.get('failure', 0)} failure,
{counts.get('in_progress', 0)} in progress and {counts.get('skipped', 0)} skipped.
This is a dated snapshot, not a claim that still-running checks subsequently
passed. All retrieved original logs, annotations, reports, process evidence and
artifact ZIPs are archived in the hosted observation and late-triage directories.
Bounded late priority/factorial triage retains full job logs, metadata and
annotations; it does not claim that every hosted artifact was downloaded or
that every still-running check was fully diagnosed. The small original CodeQL
export artifact is retained in full.

- The pinned historical artifact `11531476198` from run `37730166589` was
  unavailable: artifact API 404, original-run artifact count zero, and no
  download candidates. Its workflow is unchanged from the base. Recovery
  still requires the exact original failure data and provenance; no different
  artifact or newly generated failure is substituted.
- Original native campaign run `42463825169` built and executed three actual
  campaigns. All three failed finite confirmation/client-state criteria with
  retained `PUBLIC_REQUEST_DEADLINE` records. These are not startup failures.
  The original 71,722,426-byte artifact ZIP `13610289272` is included with SHA-256
  `b6415ddf54d336c1c0647eca920cfe7ed0dfe24b75a7d65cf9a8c5b118d6c354`.
- Four protocol/cross-architecture observations report `CONFIRMATION_TARGET`:
  each five named native controls passed, but the confirmation reader rejected
  the retained report and the native child exited 1; host-error lists were
  empty. These are separate failures from the inventory omission.
- The three late factorial jobs failed their pinned OpenSSL 3.5.9 provider
  preparation/download step with exit 22. Each later `--legal-strategy-v3`
  Python command still ran and reported PASS; the containing jobs remain
  failed. The deeper provider `build-and-smoke.log` was not retrieved, so no
  particular HTTP status or deeper root cause is claimed.
- Later service-model and other W1 observations are retained in their dedicated
  raw triage directories. The CodeQL export job reports that analyses/checks
  did not complete and stabilize before its deadline. That export failure does
  not itself establish either a vulnerability finding or successful remediation.

Unchanged workflow/test files alone do not prove an inherited runtime failure
or exclude every shared-code effect; no comparison campaign was rerun on the
base. The unavailable historical-artifact gate and confirmation thresholds
remain intact. The failed GraphQL PR-note attempt is retained even though it
has no terminal receipt; later PR text updates use the existing draft.

[Archive accounting](followup-archive-inventory.json) records every ordinary
original file, including all zero-byte logs. Raw patches and text captures with
Git whitespace diagnostics use lossless gzip with original path, size and
SHA-256 in the index; raw receipts are never rewritten. [External artifact
accounting](external-artifacts.json) explicitly records any original at least
100,000,000 bytes retained outside Git ({result['external_artifact_count']} such
files). No oversized file is silently omitted. The unused PASS-only collector
draft is identified in [its supersession record](unexecuted-collector-draft.json)
and was not executed. Previous 31-command PASS, earlier genuine Node FAIL,
research captures and all previous evidence retain their original bytes.

The draft remains **HOLD** for current native validation, hosted acceptance,
service performance, production activation, whole-chain PQ security, physical
rollback safety, WAN qualification, HeptaFinalUse and PoN quantum claims.
'''



def main(expected_head: str, validation_directory: str, expected_summary_sha256: str) -> dict:
    global CREATED_OUT
    require(expected_head == FIXED_SOURCE and validation_directory == 'inventory-source-01',
            'this reviewed one-shot collector admits only the exact inventory correction run')
    require(TASK.resolve() == TASK and REPO.resolve() == REPO and OUT.resolve() == OUT,
            'noncanonical task paths')
    OUT.mkdir(parents=True, exist_ok=False)
    CREATED_OUT = True
    (OUT / 'driver.py').write_bytes(read_bytes(Path(__file__).resolve()))
    capture = Capture()
    tree = clean_head(expected_head)
    require(tree == FIXED_TREE and git('show', '-s', '--format=%P', expected_head).decode().split() == [PUBLISHED]
            and git('rev-parse', PUBLISHED + '^{tree}').decode().strip() == PUBLISHED_TREE,
            'source correction ancestry/tree differs')
    require(git('remote', 'get-url', 'origin').decode().strip() == ORIGIN, 'unexpected origin')
    changed_source = sorted(path.decode() for path in git('diff', '--name-only', '--no-renames', '-z',
                                                         PUBLISHED, expected_head).split(b'\0') if path)
    require(changed_source == CHANGED, 'source fix does not contain the exact six reviewed paths')
    require(sha256(read_bytes(REPO / REFRESH)) == REFRESH_SHA256
            and git('show', PUBLISHED + ':' + REFRESH) == read_bytes(REPO / REFRESH), 'inventory generator changed')
    outside_before = outside_evidence_tree(expected_head)
    corpus_bytes = read_bytes(REPO / CORPUS)
    corpus = load(REPO / CORPUS)
    require(len(corpus['pinned_blobs']) == 724 and len(corpus['required_paths']) == 643
            and len(corpus['assertions']) == 8 and all(value is False for value in corpus['assertions'].values()),
            'corrected corpus count/scope differs')
    protected = set(corpus['pinned_blobs']) | set(corpus['required_paths'])
    for name in (EV_REL + '/' + RUNNER, REFRESH):
        require(name in corpus['required_paths'] and corpus['pinned_blobs'][name] == blob_id(read_bytes(REPO / name)),
                'new source input is not exactly pinned: ' + name)
    require(not {EV_REL + '/README.md', EV_REL + '/artifact-index.json'} & protected,
            'append-only metadata is unexpectedly source-pinned')
    index = load(EV / 'artifact-index.json')
    validate_index(index)
    require(len(index['files']) == 500, 'source correction must start with exactly 500 indexed files')
    old_published = json.loads(git('show', PUBLISHED + ':' + EV_REL + '/artifact-index.json'))
    require(len(old_published['files']) == 499 and RUNNER not in old_published['files'], 'published index identity differs')
    expected_index = copy.deepcopy(old_published)
    expected_index['files'][RUNNER] = {'bytes': 25774, 'sha256': RUNNER_SHA256}
    require(index == expected_index, 'source fix changed old index metadata or files')
    original, old_readme = copy.deepcopy(index), read_bytes(EV / 'README.md')
    staged_inventory(index)
    result = validate_failed_run(expected_head, tree, validation_directory, expected_summary_sha256)
    supplement = validate_fix(expected_head, tree)
    require(all(row.get('commit') != expected_head for row in index['validated_commits']), 'run already collected')
    snapshot = validate_hosted_snapshot()
    names = hosted_directories()
    archives = [FIX_DIRECTORY, validation_directory, *names]
    native_zip = TASK / 'validation/hosted-ci-native-triage-01/native-campaign-artifact-13610289272/original-artifact-13610289272.zip'
    require(file_record(native_zip) == {'bytes': 71722426,
            'sha256': 'b6415ddf54d336c1c0647eca920cfe7ed0dfe24b75a7d65cf9a8c5b118d6c354'},
            'original native campaign ZIP is missing or differs')
    preflight = json.loads(capture.run('preflight-before-evidence-edits', ['/bin/bash', 'scripts/project-preflight.sh']).stdout)
    require(preflight.get('result') == 'PASS', 'default preflight did not report PASS')
    capture.run('source-guard-before-collection', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                '--kind', 'head', '--expected-head', expected_head, '--output', str(OUT / 'verified-source-before.json')])
    require(clean_head(expected_head) == tree and isinstance(load(OUT / 'verified-source-before.json'), dict),
            'source guard or current source differs')
    external = []
    copied = {name: copy_archive(name, external) for name in archives}
    save(EV / 'followup-archive-inventory.json', {'schema': 'trnm-pq-authority-followup-archives-v1',
         'directories': copied, 'external_files': external, 'hosted_observation_source': PUBLISHED,
         'hosted_ci_passed': False, 'source_receipts_rewritten': False, 'capture_bytes_trimmed': False}, fresh=True)
    save(EV / 'external-artifacts.json', {'schema': 'trnm-pq-authority-external-artifacts-v1',
         'git_individual_file_limit_exclusive': GIT_FILE_LIMIT, 'files': external,
         'external_originals_available_at_collection': True, 'silent_omissions': False}, fresh=True)
    (EV / 'retain-authority-hold-evidence.py').write_bytes(read_bytes(Path(__file__).resolve()))
    save(EV / 'unexecuted-collector-draft.json', {'filename': 'finalize-authority-followup-evidence.py',
         'bytes': 57497, 'sha256': UNEXECUTED_DRAFT_SHA256, 'executed': False,
         'superseded_by': 'retain-authority-hold-evidence.py',
         'reason': 'The actual 32-command run failed; no PASS-only collector was executed.'}, fresh=True)
    patch = git('diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', '--no-renames', PUBLISHED, expected_head)
    with (EV / 'inventory-source-correction.patch').open('xb') as stream:
        stream.write(patch)
    correction = {'from_commit': PUBLISHED, 'from_tree': PUBLISHED_TREE, 'to_commit': expected_head,
                  'to_tree': tree, 'changed_paths': changed_source,
                  'patch': {'relative_path': 'inventory-source-correction.patch', **record(patch)},
                  'source_fix_receipt': supplement, 'native_signature_implementation_changed': False}
    save(EV / 'inventory-source-correction.json', correction, fresh=True)
    result.update(source_fix=supplement, source_correction=correction, concurrent_base_commit=UPSTREAM,
                  previous_published_commit=PUBLISHED, archived_directories=archives,
                  external_artifact_count=len(external), hosted_ci_passed=False, hosted_snapshot=snapshot)
    save(EV / 'inventory-validation-readback.json', result, fresh=True)
    require(b'## Inventory correction retained with local and hosted HOLD' not in old_readme, 'README already appended')
    (EV / 'README.md').write_bytes(old_readme + readme_section(result).encode())
    require(index['validated_commits'] == original['validated_commits'], 'a failed source cannot become a validated commit')
    index.setdefault('retained_failed_validations', []).append({'commit': expected_head, 'tree': tree,
            'directory': validation_directory, 'command_gates': 32, 'result': 'FAIL',
            'successful_command_gates': 31, 'failed_commands': ['node-release-owner'],
            'failed_node_tests': list(FAILED_NODE_TESTS), 'native_validation_passed': False,
            'summary': result['summary']})
    index.setdefault('supplementary_evidence', []).append(supplement)
    index.setdefault('followup_evidence', []).append({'tested_commit': expected_head, 'tested_tree': tree,
            'validation_directory': validation_directory, 'command_gates': 32,
            'validation_result': 'FAIL', 'native_validation_passed': False,
            'previous_published_commit': PUBLISHED, 'archived_directories': archives,
            'external_artifacts': external, 'hosted_ci_passed': False})
    deleted, compressed = set(), {}
    for name in sorted(inventory(EV, evidence=True)):
        if name not in original['files'] and Path(name).suffix in ('.raw', '.patch'):
            compressed[name + '.gz'] = compress_new(name, index, original, protected, deleted)
    rebuild_index(index, original, old_readme)
    stage(index, deleted, capture, 1)
    checked = capture.run('complete-pr-diff-check-before-capture-format',
              ['/usr/bin/git', '-c', 'core.quotePath=false', 'diff', '--cached', '--check', UPSTREAM], allowed=(0, 2))
    if checked.returncode == 2:
        headers = re.findall(r'^([^\n:]+):(\d+): ([^\n]+)$', checked.stdout.decode(errors='replace'), re.M)
        require(headers and not checked.stderr, 'unrecognized Git whitespace failure')
        paths = set()
        for path, _line, reason in headers:
            require(reason in ('trailing whitespace.', 'new blank line at EOF.', 'space before tab in indent.')
                    and path.startswith(EV_REL + '/'), 'failure is not a new capture whitespace diagnostic')
            paths.add(relative(path[len(EV_REL) + 1:]))
        for name in sorted(paths):
            compressed[name + '.gz'] = compress_new(name, index, original, protected, deleted)
        rebuild_index(index, original, old_readme)
        stage(index, deleted, capture, 2)
    capture.run('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
    capture.run('complete-pr-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check', UPSTREAM])
    changed = {path.decode() for path in git('diff', '--cached', '--name-only', '-z', expected_head).split(b'\0') if path}
    require(changed and all(path.startswith(EV_REL + '/') for path in changed), 'non-evidence staged changes')
    require(git('rev-parse', 'HEAD').decode().strip() == expected_head
            and git('branch', '--show-current').decode().strip() == BRANCH, 'HEAD moved during collection')
    require(not git('diff', '--name-only', '-z') and not git('ls-files', '--others', '--exclude-standard', '-z'),
            'unexpected unstaged or untracked files')
    require(read_bytes(REPO / CORPUS) == corpus_bytes, 'source corpus changed during collection')
    for name in protected:
        if name.startswith(EV_REL + '/'):
            require(git('show', ':' + name) == git('show', expected_head + ':' + name), 'pinned evidence input changed')
    require(hosted_directories() == names, 'hosted observation directory set changed during collection')
    for name, entry in copied.items():
        require(inventory(TASK / 'validation' / name) == entry['original_files'], 'original archive changed after copy')
    preserve_original(index, original, old_readme)
    require(index['validated_commits'] == original['validated_commits'], 'failed source promoted before commit')
    staged_inventory(index)
    save(OUT / 'precommit-readback.json', {'result': 'PASS', 'tested_commit': expected_head,
         'tested_tree': tree, 'outside_evidence_tree_sha256': sha256(outside_before),
         'artifact_files': len(index['files']), 'changed_paths': sorted(changed),
         'new_compression': compressed, 'external_artifacts': external,
         'original_500_file_identities_preserved_except_appended_readme': True,
         'source_receipts_rewritten': False, 'capture_bytes_trimmed': False,
         'validation_result': 'FAIL', 'native_validation_passed': False})
    staged_preflight = json.loads(capture.run('preflight-before-evidence-commit',
                 ['/bin/bash', 'scripts/project-preflight.sh', '--staged']).stdout)
    require(staged_preflight.get('result') == 'PASS', 'staged preflight did not report PASS')
    capture.run('commit-followup-evidence', ['/usr/bin/git', 'commit', '-m',
                'test(pq): retain failed inventory validation and draft HOLD evidence'])
    head = git('rev-parse', 'HEAD').decode().strip()
    final_tree = clean_head(head)
    require(git('show', '-s', '--format=%P', head).decode().split() == [expected_head], 'unexpected evidence commit ancestry')
    require({path.decode() for path in git('diff', '--name-only', '-z', expected_head, head).split(b'\0') if path} == changed,
            'committed evidence paths differ')
    require(outside_evidence_tree(head) == outside_before and read_bytes(REPO / CORPUS) == corpus_bytes,
            'source changed in evidence-only commit')
    require(load(EV / 'artifact-index.json') == index, 'committed artifact index differs')
    preserve_original(index, original, old_readme)
    validate_index(index)
    staged_inventory(index)
    capture.run('committed-complete-pr-diff-check', ['/usr/bin/git', 'diff', '--check', UPSTREAM, head])
    capture.run('source-guard-after-collection', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                '--kind', 'head', '--expected-head', head, '--output', str(OUT / 'verified-source-after.json')])
    require(clean_head(head) == final_tree and isinstance(load(OUT / 'verified-source-after.json'), dict),
            'source guard or final source differs')
    receipt = {'schema': 'trnm-pq-authority-followup-collection-v1', 'result': 'PASS',
               'tested_commit': expected_head, 'tested_tree': tree, 'evidence_commit': head,
               'evidence_tree': final_tree, 'command_gates': 32, 'validation_result': 'FAIL', 'native_validation_passed': False,
               'successful_command_gates': 31, 'failed_command_gates': ['node-release-owner'], 'branch': BRANCH,
               'evidence_only': True, 'all_other_source_unchanged': True,
               'artifact_files': len(index['files']), 'archived_directories': archives,
               'validation_directory': validation_directory, 'validation_summary': result['summary'],
               'hosted_snapshot': snapshot, 'external_artifacts': external,
               'new_lossless_compressions': len(compressed), 'original_hosted_failures_preserved': True,
               'original_failed_integrated_validation_preserved': True,
               'source_receipts_rewritten': False, 'capture_bytes_trimmed': False,
               'production_activation': False, 'whole_chain_pq_qualified': False, 'hosted_ci_passed': False,
               'corpus': record(corpus_bytes), 'artifact_index': file_record(EV / 'artifact-index.json')}
    save(OUT / 'receipt.json', receipt, fresh=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-summary-sha256', required=True)
    parser.add_argument('--validation-directory', required=True, choices=['inventory-source-01'])
    args = parser.parse_args()
    if not HEX64.fullmatch(args.expected_summary_sha256):
        parser.error('--expected-summary-sha256 must bind the reviewed terminal failed summary')
    if args.expected_head != FIXED_SOURCE:
        parser.error('--expected-head must be the reviewed complete inventory source SHA ' + FIXED_SOURCE)
    try:
        print(json.dumps(main(args.expected_head, args.validation_directory, args.expected_summary_sha256), sort_keys=True), flush=True)
    except Exception as error:
        failure = {'schema': 'trnm-pq-authority-followup-collection-v1', 'result': 'FAIL',
                   'expected_head': args.expected_head, 'validation_directory': args.validation_directory,
                   'error': f'{type(error).__name__}: {error}', 'failure_preserved_without_reset': True,
                   'production_activation': False, 'whole_chain_pq_qualified': False, 'hosted_ci_passed': False}
        if CREATED_OUT and OUT.is_dir() and not (OUT / 'receipt.json').exists():
            if not (OUT / 'failure.json').exists():
                save(OUT / 'failure.json', failure, fresh=True)
                with (OUT / 'failure-traceback.txt').open('x', encoding='utf-8') as stream:
                    traceback.print_exc(file=stream)
        print(json.dumps(failure, sort_keys=True), file=sys.stderr, flush=True)
        raise SystemExit(1)
