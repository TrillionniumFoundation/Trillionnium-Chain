#!/usr/bin/env python3
"""Archive the completed, exact-source 31-gate PQ authority run.

One-shot driver for the fixed task checkout. Invoke only after reviewing this
file and after the selected corrected-source run has completed:

    python3 -B finalize-authority-evidence.py --expected-head <tested-SHA> \
        --validation-directory integrated-source-02

No Cargo, network, source edits, receipt rewrites, push or activation. Original
capture bytes are copied unchanged or losslessly gzipped. A normal Git commit
records only this task's evidence directory. A failed attempt is kept in the
external final-evidence-collection-01 directory and is never overwritten.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import traceback


TASK = Path('/home/qian-qi/work/chain-pq-authority-20261108-9d315')
REPO = TASK / 'repo'
OUT = TASK / 'validation/final-evidence-collection-01'
EV_REL = 'evidence/pq-authority-preflight-20261108-9d315'
EV = REPO / EV_REL
PREP = TASK / 'integration-preparation-01'
BASE = '12e510b211110d93d9ead07e02c07a1eecc28ae9'
BASE_TREE = 'a8c9634b9e0d59ccc9fd6a03875eee7fc76c099f'
FIRST = '62ed4e4facae4e0eb9f3fdeb82001acb3b21be47'
FIRST_TREE = '38a1d4da1a6dc8c93d49ca181c8e35ecb79ef776'
FIRST_SUMMARY_SHA256 = '4069a4223204258abd0aae53df9e2412a33152a1ae4b87b3f8545c343fe03b1a'
UPSTREAM = '8d8f05566b2a1612a3bf4a6c6c71635df454d397'
MERGED = 'af6b06fa1cb944e639148b58e9765fe2bb0065ab'
MERGED_TREE = '5c624c637c9db17e0a7410d112369ad7b3bb2d73'
BRANCH = 'fix/chain-pq-authority-preflight-20261108-9d315'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
RUNNER = 'authority-integrated-validation-runner.py'
RUNNER_SHA256 = 'f5fc66625c09cfccf5054ec705a49c2a88f234c0620e6e6426aa4b7efcb71b86'
MERGE_ARCHIVES = ('concurrent-base-integration-01', 'concurrent-base-integration-recovery-01')
FIX_DIRECTORY = 'node-expiry-fixture-fix-01'
FIX_DRIVER_SHA256 = 'c0d6a67596295ca5172ea641502c1007a6025f293b2eb0b3bfc2bcfccfcb9cde'
FIX_TEST_PATH = 'trillionnium/crates/trnm-pon-node/src/release_owner/service_tests.rs'
FIX_REPORT_PATH = 'docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md'
FIX_TEST_NAME = ('release_owner::service_tests::'
                 'admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch')
FIX_BEFORE_SHA256 = '1b47a8384fa20bfd7c2a15c41f4a693eb8cede29c8100f45885d8ac80e66fee0'
FIX_PROPOSAL_SHA256 = '8f12bea3c6c3fc505c18d43844a7d86f6471988ba89bab1e61a9ea7457fa5f82'
FAILED_SUMMARY_SHA256 = 'f914399f9b6ea68ef81e56fc3ff53b4164ddf59df2dcbbf8b0f984f7009ade39'
FIX_COMMAND_LABELS = ('preflight-before-edit', 'rustfmt-reviewed-test', 'diff-check',
                      'ci-contract', 'pq-integration', 'stage-reviewed-paths', 'staged-diff-check',
                      'preflight-before-commit', 'commit-reviewed-fix', 'preflight-before-test',
                      'node-expiry-exact-native')
LOCK_NAME = re.compile(r'\.hepta-lock-[0-9a-f]{24}')
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')
READERS = (
    ('preflight', 'preflight'), ('source-guard-before', 'source'),
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
LIBTEST_SUMMARY = re.compile(
    r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; '
    r'(\d+) measured; (\d+) filtered out;.*$', re.M)
LIBTEST_NAME = re.compile(r'^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored(?:,.*)?)$', re.M)
LIBTEST_ANY_SUMMARY = re.compile(
    r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
    r'(\d+) measured; (\d+) filtered out;.*$', re.M)
PROVIDER_ROOT = Path('/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2')
PROVIDER = PROVIDER_ROOT / 'build-runtime/trnm-pq-provider-3.5.9.DYf2qEaX/install'
PROVIDER_FILES = {
    'bin/openssl': (8933408, '8ff7dd91270fd4a8fc377031f0fd2f2cee1cd17a32ce30e4fd773a25730a120f'),
    'include/openssl/opensslv.h': (3449, '9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda'),
    'include/openssl/configuration.h': (4729, '406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996'),
    'lib/libcrypto.a': (12381776, 'dabf2189afd2e29591c5b597ac2cb9b7cd7066eaf7ce674106123614da32eb0f'),
    'lib/libssl.a': (2123138, 'f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727'),
}
ENV = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
ENV.update(GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0',
           PYTHONDONTWRITEBYTECODE='1', LANG='C.UTF-8', LC_ALL='C.UTF-8', TZ='UTC')
CREATED_OUT = False


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


def inventory(root: Path, *, evidence: bool = False) -> dict[str, dict]:
    require(root.is_dir() and root.resolve() == root, 'invalid inventory root: ' + str(root))
    files = {}
    for path in sorted(root.rglob('*')):
        st = path.lstat()
        require(not stat.S_ISLNK(st.st_mode), 'symlink in retained tree: ' + str(path))
        if stat.S_ISDIR(st.st_mode):
            continue
        name = relative(path.relative_to(root).as_posix())
        data = read_bytes(path)
        if LOCK_NAME.fullmatch(path.name):
            require(not data, 'nonempty tool lock: ' + str(path))
            continue
        if evidence and name == 'artifact-index.json':
            continue
        files[name] = record(data)
    return files


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


def validate_index(index: dict) -> None:
    require(index.get('schema') == 'trnm-pq-authority-artifacts-v1', 'unexpected artifact index schema')
    require(index.get('base_commit') == BASE and index.get('base_tree') == BASE_TREE,
            'original authority base identity changed')
    require(index.get('concurrent_base_commit') == UPSTREAM, 'upstream integration base differs')
    require(index.get('production_activation') is False and index.get('whole_chain_pq_qualified') is False,
            'artifact index must preserve held scope')
    require(isinstance(index.get('frozen_research_source_sha256'), dict)
            and index['frozen_research_source_sha256'], 'missing frozen research identities')
    require(index.get('files') == inventory(EV, evidence=True), 'artifact index is not the exact file inventory')
    require(isinstance(index.get('compression'), dict), 'missing original compression mapping')
    for compressed, details in index['compression'].items():
        compressed = relative(compressed)
        require(compressed.endswith('.gz') and compressed in index['files'], 'unindexed gzip entry')
        data = read_bytes(EV / compressed)
        check_record(data, {'bytes': details.get('compressed_bytes'),
                           'sha256': details.get('compressed_sha256')}, compressed)
        raw = gzip.decompress(data)
        check_record(raw, details.get('uncompressed'), 'decompressed ' + compressed)
        raw_path = details['uncompressed'].get('relative_path')
        if raw_path is not None:
            relative(raw_path)
            require(raw_path != compressed, 'compression maps a file to itself')


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


def validate_run(expected_head: str, tree: str, directory: str) -> dict:
    source = TASK / 'validation' / directory
    summary = load(source / 'summary.json')
    require(summary.get('schema') == 'trnm-pq-authority-validation-v1'
            and summary.get('result') == 'PASS' and summary.get('failures') == []
            and summary.get('expected_head') == expected_head and summary.get('repo') == str(REPO),
            'integrated summary is not a successful exact-source run')
    require(summary.get('source_unchanged') is True and summary.get('provider_unchanged') is True
            and summary.get('production_activation') is False
            and summary.get('whole_chain_quantum_security_qualified') is False, 'run source/provider/scope guard failed')
    rows = summary.get('commands')
    specs = load(source / 'commands.json')
    require(isinstance(rows, list) and len(rows) == 31
            and [(s['label'], s['reader']) for s in specs] == list(READERS)
            and [r['label'] for r in rows] == [name for name, _ in READERS], 'not the exact reviewed 31 gates')
    runner = read_bytes(source / 'authority-validation-runner.py')
    require(sha256(runner) == RUNNER_SHA256 and runner == read_bytes(EV / RUNNER),
            'retained runner differs from the committed integrated runner')
    check_record(runner, summary.get('runner'), 'retained integrated runner')
    require(summary['runner'].get('path') == str(source / 'authority-validation-runner.py'), 'runner receipt path differs')
    native, python = {}, {}
    for spec, row, (_, reader) in zip(specs, rows, READERS):
        label = row['label']
        require(row.get('passed') is True and type(row.get('exit_code')) is int
                and row['exit_code'] == 0 and not row.get('timed_out')
                and not row.get('blocked') and not row.get('error')
                and row.get('argv') == spec['argv'] and row.get('cwd') == str(REPO),
                'gate did not complete successfully: ' + label)
        require(load(source / (label + '.receipt.json')) == row, 'summary/individual receipt differs: ' + label)
        names = [label + '.stdout.log', label + '.stderr.log']
        require(set(row.get('logs', {})) == set(names), 'gate did not retain both output streams')
        stdout, stderr = [validate_raw_log_record(source, name, row['logs'][name]) for name in names]
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
                       'six-package-doc-tests': (4, 0, 0), 'node-release-owner': (40, 1, 1244)}
    for label, expected in expected_native.items():
        values = native[label]
        require((values['passed'], values['ignored'], values['filtered']) == expected
                and values['failed'] == 0 and values['measured'] == 0, 'reviewed native scope differs: ' + label)
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
    return {'result': 'PASS', 'tested_commit': expected_head, 'tested_tree': tree,
            'validation_directory': directory, 'command_gates': len(rows),
            'native': native, 'python': python, 'summary': record(read_bytes(source / 'summary.json')),
            'source_unchanged': True, 'provider_unchanged': True, 'sqlite_qualified': True,
            'production_activation': False, 'whole_chain_pq_qualified': False}


def validate_failed_run(directory: str, tested_head: str) -> dict:
    """Retain a completed failure honestly; never use it to authorize success."""
    source = TASK / 'validation' / directory
    summary = load(source / 'summary.json')
    old_head = summary.get('expected_head', '')
    require(summary.get('schema') == 'trnm-pq-authority-validation-v1'
            and summary.get('result') == 'FAIL' and HEX40.fullmatch(old_head) is not None
            and summary.get('repo') == str(REPO)
            and summary.get('production_activation') is False
            and summary.get('whole_chain_quantum_security_qualified') is False,
            'prior validation is not a retained exact-source failure: ' + directory)
    git('merge-base', '--is-ancestor', old_head, tested_head)
    if directory == 'integrated-source-01':
        require(old_head == MERGED, 'first integrated failure belongs to a different source')
    old_tree = git('rev-parse', old_head + '^{tree}').decode().strip()
    before, after = load(source / 'source-before.json'), load(source / 'source-after.json')
    require(before == after and before.get('head') == old_head and before.get('tree') == old_tree
            and before.get('branch') == BRANCH and before.get('status') == ''
            and summary.get('source_unchanged') is True, 'prior failed run did not preserve its stated source')
    require(load(source / 'provider-before.json') == load(source / 'provider-after.json')
            and summary.get('provider_unchanged') is True, 'prior failed run provider identity differs')
    rows, specs = summary.get('commands', []), load(source / 'commands.json')
    require(len(rows) == 31 and [row.get('label') for row in rows] == [name for name, _ in READERS]
            and [(entry['label'], entry['reader']) for entry in specs] == list(READERS),
            'prior failed run is not complete; wait for all independent gates to finish')
    runner = read_bytes(source / 'authority-validation-runner.py')
    require(sha256(runner) == RUNNER_SHA256, 'prior failed run used a different integrated runner')
    check_record(runner, summary.get('runner'), 'prior failed runner')
    failed_labels, native = [], {}
    for row, spec, (_, reader) in zip(rows, specs, READERS):
        label = row['label']
        require(type(row.get('passed')) is bool and type(row.get('exit_code')) is int
                and row.get('argv') == spec['argv'] and row.get('cwd') == str(REPO)
                and load(source / (label + '.receipt.json')) == row,
                'prior failed run command receipt differs: ' + label)
        if row['passed']:
            require(row['exit_code'] == 0 and not row.get('error') and not row.get('timed_out')
                    and not row.get('blocked'), 'prior passing command has failure metadata')
        else:
            failed_labels.append(label)
        names = [label + '.stdout.log', label + '.stderr.log']
        require(set(row.get('logs', {})) == set(names), 'prior command lost an output stream')
        stdout, stderr = [validate_raw_log_record(source, name, row['logs'][name]) for name in names]
        if reader in ('release-tests', 'rust-tests', 'rust-docs', 'node-tests'):
            text = stdout.decode(errors='replace')
            summaries = LIBTEST_ANY_SUMMARY.findall(text)
            values = [list(map(int, item[1:])) for item in summaries]
            require(values, 'prior native output lost its actual result summary')
            native[label] = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered'),
                                     (sum(item[i] for item in values) for i in range(5))))
            native[label]['statuses'] = [item[0] for item in summaries]
            native[label]['failed_names'] = [name for name, outcome in LIBTEST_NAME.findall(text) if outcome == 'FAILED']
        if row['passed'] and reader in ('unittest', 'release-tests', 'rust-tests', 'rust-docs', 'node-tests'):
            parse_counts(row, stdout, stderr, reader)
    require(failed_labels or summary.get('failures'), 'FAIL summary has no failure evidence')
    if directory == 'integrated-source-01':
        require(failed_labels == ['node-release-owner'], 'first integrated failure scope differs from the reviewed event')
        node = native['node-release-owner']
        require((node['passed'], node['failed'], node['ignored'], node['filtered']) == (39, 1, 1, 1244),
                'first integrated Node failure counts changed')
        require(node['failed_names'] == [
            'release_owner::service_tests::admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch'],
            'first integrated Node failure identity changed')
    return {'result': 'FAIL', 'directory': directory, 'commit': old_head, 'tree': old_tree,
            'command_gates': len(rows), 'failed_commands': failed_labels, 'failures': summary.get('failures'),
            'native': native, 'summary': record(read_bytes(source / 'summary.json')),
            'source_unchanged': True, 'provider_unchanged': True,
            'production_activation': False, 'whole_chain_pq_qualified': False}


def validate_fixture_fix(expected_head: str, tree: str, validation_directory: str) -> dict:
    source = TASK / 'validation' / FIX_DIRECTORY
    receipt = load(source / 'receipt.json')
    changed_paths = sorted((FIX_TEST_PATH, FIX_REPORT_PATH, CORPUS))
    require(receipt.get('schema') == 'trnm-pq-node-expiry-fixture-fix-v1'
            and receipt.get('result') == 'PASS' and receipt.get('failures') == []
            and receipt.get('parent_commit') == MERGED and receipt.get('source_commit') == expected_head
            and receipt.get('source_tree') == tree and receipt.get('branch') == BRANCH
            and receipt.get('changed_paths') == changed_paths and receipt.get('exact_test_name') == FIX_TEST_NAME,
            'fixture-fix supplement is not a successful record on the selected tested source')
    for name in ('production_sources_changed', 'production_activation', 'whole_chain_pq_qualified', 'full_validation_executed'):
        require(receipt.get(name) is False, 'supplement changed its bounded claim: ' + name)
    for name in ('source_unchanged_during_test', 'provider_unchanged', 'sqlite_qualified'):
        require(receipt.get(name) is True, 'supplementary test boundary did not pass: ' + name)
    require(sha256(read_bytes(source / 'apply-node-expiry-fixture-fix.py')) == FIX_DRIVER_SHA256,
            'supplementary fix driver differs from reviewed source')
    require(git('show', '-s', '--format=%P', expected_head).decode().split() == [MERGED]
            and sorted(git('diff', '--name-only', MERGED, expected_head).decode().splitlines()) == changed_paths,
            'fixture correction changed more than the three reviewed paths')
    rows = receipt.get('commands', [])
    require([row.get('label') for row in rows] == list(FIX_COMMAND_LABELS),
            'supplement does not contain the exact eleven recorded commands')
    native = None
    for row in rows:
        label = row['label']
        require(row.get('passed') is True and type(row.get('exit_code')) is int and row['exit_code'] == 0
                and not row.get('error') and not row.get('timed_out') and not row.get('blocked')
                and row.get('cwd') == str(REPO) and load(source / (label + '.receipt.json')) == row,
                'supplementary command failed or receipt differs: ' + label)
        names = [label + '.stdout.log', label + '.stderr.log']
        require(set(row.get('logs', {})) == set(names), 'supplementary command lost an output stream')
        stdout, stderr = [validate_raw_log_record(source, name, row['logs'][name]) for name in names]
        if label == 'node-expiry-exact-native':
            native = parse_counts(row, stdout, stderr, 'node-tests')
        elif label.startswith('preflight-') or label in ('ci-contract', 'pq-integration'):
            value = json.loads(stdout)
            require(value == row.get('readback'), 'supplementary JSON receipt/raw mismatch')
            if label.startswith('preflight-'):
                require(value.get('result') == 'PASS', 'supplementary preflight failed')
            if label == 'pq-integration':
                require(value.get('status') == 'HOLD_NO_GO' and value.get('cryptographic_acceptance') is False
                        and value.get('node_activated') is False, 'supplementary PQ guard changed scope')
    target = rows[-1]
    require(receipt.get('targeted_test') == target and native['summaries'] == [[1, 0, 0, 0, 1284]]
            and native['passed_names'] == [FIX_TEST_NAME] and native['ignored_names'] == [],
            'supplement is not the one exact native expiry test')
    require(target['argv'] == [
        '/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo',
        'test', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml',
        '-p', 'trnm-pon-node', '--lib', '--all-features', FIX_TEST_NAME,
        '--', '--exact', '--show-output', '--test-threads=1'], 'supplementary native selector differs')
    prior = TASK / 'validation/integrated-source-01'
    selected = TASK / 'validation' / validation_directory
    original = receipt.get('original_failed_run', {})
    require(original.get('directory') == 'integrated-source-01' and original.get('source_commit') == MERGED
            and original.get('result') == 'FAIL' and original.get('failed_command') == 'node-release-owner'
            and original.get('failed_test') == FIX_TEST_NAME, 'supplement relabelled the original failure')
    prior_summary = read_bytes(prior / 'summary.json')
    require(sha256(prior_summary) == FAILED_SUMMARY_SHA256, 'original failed summary identity differs')
    check_record(prior_summary, original.get('summary'), 'supplement original-failure summary')
    require(original['summary'].get('path') == str(prior / 'summary.json'), 'prior summary path differs')
    parent = load(source / 'source-parent.json')
    before, after = load(source / 'source-before.json'), load(source / 'source-after.json')
    require(parent == load(prior / 'source-after.json') and parent.get('head') == MERGED
            and parent.get('tree') == MERGED_TREE and parent.get('status') == '', 'supplement parent boundary differs')
    require(before == after == load(selected / 'source-before.json')
            and before.get('head') == expected_head and before.get('tree') == tree and before.get('status') == '',
            'supplementary test and full validation used different source identities')
    provider = load(source / 'provider-parent.json')
    require(provider == load(prior / 'provider-after.json') == load(source / 'provider-before.json')
            == load(source / 'provider-after.json') == load(selected / 'provider-before.json'),
            'supplement provider differs across the retained execution boundaries')
    test_source = receipt.get('test_source', {})
    retained_tests = {}
    for key, name in (('before', 'service-tests-before.raw'),
                      ('reviewed_proposal', 'service-tests-reviewed-proposal.raw'),
                      ('formatted', 'service-tests-formatted.raw')):
        retained_tests[key] = read_bytes(source / name)
        require(test_source.get(key, {}).get('path') == str(source / name), 'retained fixture source path differs')
        check_record(retained_tests[key], test_source[key], name)
    require(sha256(retained_tests['before']) == FIX_BEFORE_SHA256
            and retained_tests['before'] == git('show', MERGED + ':' + FIX_TEST_PATH)
            and sha256(retained_tests['reviewed_proposal']) == FIX_PROPOSAL_SHA256
            and retained_tests['formatted'] == git('show', expected_head + ':' + FIX_TEST_PATH)
            and test_source.get('formatting_changed_bytes') is (retained_tests['formatted'] != retained_tests['reviewed_proposal']),
            'reviewed/formatted fixture bytes do not match their source commits')
    require(read_bytes(source / 'report-before.raw') == git('show', MERGED + ':' + FIX_REPORT_PATH)
            and read_bytes(source / 'report-after.raw') == git('show', expected_head + ':' + FIX_REPORT_PATH),
            'retained report snapshots differ from committed source')
    require(read_bytes(source / 'source-correction.patch') ==
            git('diff', '--binary', '--no-ext-diff', '--no-textconv', MERGED, expected_head),
            'supplementary source patch differs from the three-path correction')
    old_corpus = json.loads(git('show', MERGED + ':' + CORPUS))
    new_corpus = json.loads(git('show', expected_head + ':' + CORPUS))
    require(set(old_corpus) == set(new_corpus)
            and {key for key in old_corpus if old_corpus[key] != new_corpus[key]} == {'pinned_blobs'}
            and set(old_corpus['pinned_blobs']) == set(new_corpus['pinned_blobs'])
            and {key for key in old_corpus['pinned_blobs']
                 if old_corpus['pinned_blobs'][key] != new_corpus['pinned_blobs'][key]} == {FIX_TEST_PATH, FIX_REPORT_PATH},
            'fixture correction changed corpus semantics beyond its two refreshed pins')
    sqlite = load(source / 'sqlite-qualification.json')
    require(sqlite.get('passed') is True and sqlite.get('outputs'), 'supplementary SQLite qualification failed')
    output_names = []
    for item in sqlite['outputs']:
        path = Path(item['retained']['path'])
        require(path.parent == source / 'sqlite-build-outputs' and item.get('qualified') is True,
                'supplementary SQLite output is unqualified or misplaced')
        data = read_bytes(path)
        check_record(data, item['retained'], 'supplement SQLite output')
        require(b'cargo:rustc-cfg=trnm_sqlite_layout_witness\n' in data
                and b'cargo:rustc-env=TRNM_SQLITE3_BUILD_FENCE=sqlite-3.51.3-normal-native-linux-layout-v3\n' in data
                and b'UNQUALIFIED:' not in data and b'TRNM_SQLITE3_UNQUALIFIED_REASON=' not in data,
                'supplementary SQLite markers do not qualify')
        output_names.append(path.name)
    require(len(output_names) == len(set(output_names))
            and set(output_names) == set(inventory(source / 'sqlite-build-outputs')),
            'supplementary SQLite receipt omits a retained output')
    return {'directory': FIX_DIRECTORY, 'result': 'PASS', 'parent_commit': MERGED,
            'source_commit': expected_head, 'source_tree': tree,
            'recorded_commands': len(rows), 'native_test': native,
            'receipt': record(read_bytes(source / 'receipt.json')),
            'production_sources_changed': False, 'full_validation_executed': False,
            'adds_to_full_validation_gate_count': False,
            'source_unchanged_during_test': True, 'provider_unchanged': True, 'sqlite_qualified': True}


def validate_merge_attempts() -> bytes:
    failed = TASK / 'validation/concurrent-base-integration-01'
    recovered = TASK / 'validation/concurrent-base-integration-recovery-01'
    failed_rows = load(failed / 'commands.json')
    require(failed_rows and failed_rows[-1]['label'] == 'staged-diff-check'
            and failed_rows[-1]['exit_code'] == 2, 'missing original archive-format refusal')
    require(not (failed / 'receipt.json').exists(), 'original failed integration unexpectedly has a final receipt')
    for directory in (failed, recovered):
        rows = load(directory / 'commands.json')
        require(len(rows) == len({row['label'] for row in rows}), 'duplicate integration command labels')
        for row in rows:
            require(set(row['logs']) == {row['label'] + '.stdout.log', row['label'] + '.stderr.log'},
                    'integration command lost an output stream')
            for name, expected in row['logs'].items():
                validate_raw_log_record(directory, name, expected)
    receipt = load(recovered / 'receipt.json')
    require(receipt.get('result') == 'PASS' and receipt.get('source_commit') == MERGED
            and receipt.get('source_tree') == MERGED_TREE and receipt.get('parents') == [FIRST, UPSTREAM]
            and receipt.get('branch') == BRANCH and receipt.get('pinned_blobs') == 722
            and receipt.get('required_paths') == 641 and receipt.get('first_validation_commit') == FIRST
            and receipt.get('first_validation_gates') == 28
            and receipt.get('native_source_unchanged_from_first_validation') is True
            and receipt.get('integrated_validation_executed') is False
            and receipt.get('original_failed_attempt_preserved') is True
            and receipt.get('production_activation') is False and receipt.get('whole_chain_pq_qualified') is False,
            'merge recovery receipt does not match the original integrated source')
    counts = read_bytes(PREP / 'first-validation-counts.json')
    require(counts == read_bytes(recovered / 'first-validation-counts.json'), 'first-counts copy differs')
    parsed = json.loads(counts)
    require(parsed.get('result') == 'PASS' and parsed.get('source_commit') == FIRST, 'invalid first-run count readback')
    old_summary = read_bytes(EV / 'committed-source-01/summary.json')
    require(sha256(old_summary) == FIRST_SUMMARY_SHA256, 'original 28-gate summary bytes changed')
    old = json.loads(old_summary)
    require(old.get('result') == 'PASS' and old.get('expected_head') == FIRST and old.get('failures') == []
            and len(old.get('commands', [])) == 28 and all(row.get('passed') is True for row in old['commands'])
            and old.get('source_unchanged') is True and old.get('provider_unchanged') is True,
            'original validation is not the separately retained 28-gate run')
    return counts


def check_existing_archive(source: Path, destination: Path, index: dict, before: dict) -> dict:
    stored = set()
    for name, expected in before.items():
        raw_name = (destination / name).relative_to(EV).as_posix()
        if (EV / raw_name).exists():
            physical, data = raw_name, read_bytes(EV / raw_name)
        else:
            physical = raw_name + '.gz'
            require(physical in index['compression'], 'existing archive lost raw capture: ' + raw_name)
            details = index['compression'][physical]
            require(details['uncompressed'].get('relative_path', raw_name) == raw_name,
                    'existing archive compression maps a different original path')
            encoded = read_bytes(EV / physical)
            check_record(encoded, index['files'][physical], physical)
            data = gzip.decompress(encoded)
            check_record(data, details['uncompressed'], raw_name)
        check_record(data, expected, 'existing raw archive ' + raw_name)
        stored.add((EV / physical).relative_to(destination).as_posix())
    require(set(inventory(destination)) == stored and inventory(source) == before,
            'existing archive is not the exact complete source directory')
    return before


def copy_archive(source: Path, destination: Path, index: dict) -> dict:
    before = inventory(source)
    require(before, 'empty validation directory')
    if destination.exists():
        return check_existing_archive(source, destination, index, before)
    destination.mkdir()
    # Keep empty directories and, in particular, zero-byte stdout/stderr files.
    for directory in sorted(path for path in source.rglob('*') if path.is_dir()):
        (destination / directory.relative_to(source)).mkdir(parents=True, exist_ok=True)
    for name, expected in before.items():
        data = read_bytes(source / name)
        check_record(data, expected, name)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    require(inventory(source) == before == inventory(destination), 'source changed during archive copy')
    return before


def compress_capture(name: str, index: dict, protected: set[str], deleted: set[str], original_tracked: set[str]) -> dict:
    name = relative(name)
    require(name not in ('README.md', 'artifact-index.json') and EV_REL + '/' + name not in protected,
            'refusing to compress protected evidence/source: ' + name)
    source, destination = EV / name, EV / (name + '.gz')
    require(not name.endswith('.gz') and not destination.exists() and name + '.gz' not in index['compression'],
            'gzip collision or repeated compression: ' + name)
    data = read_bytes(source)
    encoded = gzip.compress(data, compresslevel=9, mtime=0)
    require(gzip.decompress(encoded) == data, 'lossless gzip roundtrip failed')
    with destination.open('xb') as stream:
        stream.write(encoded)
    require(read_bytes(source) == data and gzip.decompress(read_bytes(destination)) == data,
            'capture changed during compression')
    details = {'compressed_bytes': len(encoded), 'compressed_sha256': sha256(encoded),
               'uncompressed': {**record(data), 'relative_path': name}}
    index['compression'][name + '.gz'] = details
    source.unlink()
    if EV_REL + '/' + name in original_tracked:
        deleted.add(EV_REL + '/' + name)
    readme = read_bytes(EV / 'README.md').decode()
    rewritten = readme.replace('](' + name + ')', '](' + name + '.gz)')
    if rewritten != readme:
        (EV / 'README.md').write_text(rewritten, encoding='utf-8')
    return details


def rebuild_index(index: dict, original: dict) -> None:
    for key, value in original.items():
        if key not in ('files', 'compression', 'validated_commits', 'retained_failed_validations', 'supplementary_evidence'):
            require(index.get(key) == value, 'immutable artifact metadata changed: ' + key)
    for name, value in original['compression'].items():
        require(index['compression'].get(name) == value, 'original compression record changed')
    require(index['validated_commits'][:len(original['validated_commits'])] == original['validated_commits'],
            'original validated-commit records changed')
    retained_failures = original.get('retained_failed_validations', [])
    require(index.get('retained_failed_validations', [])[:len(retained_failures)] == retained_failures,
            'original failed-validation records changed')
    supplements = original.get('supplementary_evidence', [])
    require(index.get('supplementary_evidence', [])[:len(supplements)] == supplements,
            'original supplementary evidence records changed')
    index['files'] = inventory(EV, evidence=True)
    save(EV / 'artifact-index.json', index)
    validate_index(index)


def staged_inventory(index: dict) -> None:
    entries = {}
    for row in git('ls-files', '--stage', '-z', '--', EV_REL).split(b'\0'):
        if not row:
            continue
        header, path = row.split(b'\t', 1)
        mode, oid, stage = header.decode().split()
        name = path.decode()
        require(stage == '0' and mode in ('100644', '100755'), 'nonregular or unmerged evidence index entry')
        entries[name] = oid
    expected = {EV_REL + '/' + name: value for name, value in index['files'].items()}
    expected[EV_REL + '/artifact-index.json'] = record(read_bytes(EV / 'artifact-index.json'))
    require(set(entries) == set(expected), 'staged evidence inventory has extra or missing files')
    # Read the actual staged Git blobs, not only the working-tree copies.
    process = subprocess.Popen(['/usr/bin/git', '-C', str(REPO), 'cat-file', '--batch'],
                               env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for path in sorted(expected):
            oid = entries[path]
            process.stdin.write((oid + '\n').encode())
            process.stdin.flush()
            header = process.stdout.readline().decode().strip().split()
            require(len(header) == 3 and header[0] == oid and header[1] == 'blob', 'invalid staged blob response')
            size = int(header[2])
            data = process.stdout.read(size)
            require(len(data) == size and process.stdout.read(1) == b'\n', 'truncated staged Git blob')
            check_record(data, expected[path], 'staged ' + path)
            require(blob_id(data) == oid, 'staged blob ID mismatch')
        process.stdin.close()
        require(process.wait() == 0, 'staged blob reader failed')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def stage(index: dict, deleted: set[str], capture: Capture, number: int) -> None:
    paths = sorted({EV_REL + '/' + name for name in index['files']} |
                   {EV_REL + '/artifact-index.json'} | deleted)
    # Exact pathspecs also record explicitly known raw-file deletions; no broad add.
    capture.run('stage-exact-inventory-' + str(number),
                ['/usr/bin/git', 'add', '--force', '--', *paths])
    staged_inventory(index)
    # A raw path removed from the index no longer matches a later git-add
    # pathspec. Subsequent rounds must stage only newly observed deletions.
    deleted.clear()


def outside_evidence_tree(commit: str) -> bytes:
    return b'\0'.join(row for row in git('ls-tree', '-r', '-z', commit).split(b'\0')
                      if row and not row.split(b'\t', 1)[1].startswith((EV_REL + '/').encode()))


def readme_section(result: dict) -> str:
    native, python = result['native'], result['python']
    directory = result['validation_directory']
    failed = result['retained_failed_validations'][0]
    failed_node = failed['native']['node-release-owner']
    supplement = result['supplementary_evidence'][0]
    rows = []
    for label, title in (('release-all-targets', 'Release bundle'),
                         ('five-package-all-targets', 'Other five selected packages'),
                         ('six-package-doc-tests', 'Six-package doctests'),
                         ('node-release-owner', 'Node `release_owner::` only')):
        count = native[label]
        rows.append(f"| {title} | {count['passed']:,} | {count['ignored']:,} | {count['filtered']:,} |")
    python_rows = [f"| `{label}` | {values['tests']:,} |" for label, values in python.items()]
    return (
        '\n## Exact-source validation after concurrent-base integration\n\n'
        f"The [corrected-source run]({directory}/summary.json) passed all **{result['command_gates']} command gates**\n"
        f"on `{result['tested_commit']}` (tree `{result['tested_tree']}`).\n"
        'The counts below are read from the retained command receipts and checked\n'
        'against their exact stdout/stderr bytes by the\n'
        '[collection readback](integrated-validation-readback.json).\n\n'
        '| Native test scope | Passed | Ignored | Filtered |\n| --- | ---: | ---: | ---: |\n'
        + '\n'.join(rows) + '\n\n'
        'Every supplied release test name matches the complete 37 + 6 + 9 roster.\n'
        'The ignored cost observations and isolated fixed-root control remain\n'
        'explicitly ignored. This is not a full Node test run, an all-workspace\n'
        'test run, or full Node/Host acceptance. Strict workspace Clippy, formatting,\n'
        'the locked offline dependency graphs, source guards and repository checks\n'
        'are separate passing gates in the retained run.\n\n'
        '| Python command gate | Tests reported |\n| --- | ---: |\n'
        + '\n'.join(python_rows) + '\n\n'
        f"The {python['pq-root-quorum-research']['tests']} root research unit tests exercise encoding and policy with\n"
        'test doubles. They are separate from the earlier native provider experiment.\n'
        'Before/after source and provider identities match. The retained SQLite\n'
        'build-script outputs contain the required native qualification markers.\n\n'
        f"The [original 28-gate run](committed-source-01/summary.json) remains attributed to `{FIRST}`\n"
        f"(tree `{FIRST_TREE}`), before the concurrent-base merge.\n"
        'Its [count readback](first-validation-counts.json) is retained separately.\n'
        'Those old results are not relabelled as results on the integrated commit.\n\n'
        f"The [first integrated run](integrated-source-01/summary.json) remains **FAIL** on `{failed['commit']}`.\n"
        f"Its Node scope reported {failed_node['passed']} passed, {failed_node['failed']} failed,\n"
        f"{failed_node['ignored']} ignored and {failed_node['filtered']:,} filtered tests. The failing gate was\n"
        '`node-release-owner`; its original failure, output streams and receipts\n'
        'are retained without alteration. The successful corrected-source run\n'
        'above does not replace or relabel this failed attempt.\n\n'
        'The exact source changes from the failed merge to the successfully tested\n'
        'successor are recorded in the [binary Git patch](source-correction.patch.gz)\n'
        'and [commit/tree/path record](source-correction.json). The final evidence\n'
        'commit changes no files outside this task evidence directory relative\n'
        'to that successfully tested successor.\n\n'
        'The [fixture-correction supplement](node-expiry-fixture-fix-01/receipt.json)\n'
        f"retains {supplement['recorded_commands']} driver commands and a separate\n"
        '[exact native test](node-expiry-fixture-fix-01/node-expiry-exact-native.receipt.json).\n'
        f"That targeted run reports {supplement['native_test']['passed']} passed,\n"
        f"{supplement['native_test']['ignored']} ignored and {supplement['native_test']['filtered']:,} filtered tests\n"
        'on the same corrected source commit, with unchanged source/provider\n'
        'identities and qualified retained SQLite outputs. Its\n'
        '`full_validation_executed:false` remains unchanged: this one-test\n'
        'supplement does not increase the 31 command gates or the Node total\n'
        'reported for the complete selected run above.\n\n'
        'The complete [initial integration attempt](concurrent-base-integration-01/commands.json)\n'
        'is retained with its final whitespace-check refusal (exit 2) and without\n'
        'a success receipt. The [recovery receipt](concurrent-base-integration-recovery-01/receipt.json)\n'
        'records the completed merge; it predates the integrated validation above.\n\n'
        'All captured streams, including empty files, are retained. Raw `.patch`\n'
        'and `.raw` artifacts, and captures rejected by Git whitespace checks, are\n'
        'stored as lossless gzip. `artifact-index.json` maps stored gzip bytes to\n'
        'the original byte length, SHA-256 and relative path. Receipt paths and\n'
        'hashes are left unchanged; captured bytes are never trimmed or rewritten.\n\n'
        '**Scope remains HOLD:** production activation and whole-chain PQ\n'
        'qualification remain false. This evidence does not establish full\n'
        'entrypoint migration, independent custody or recovery, original fixed-Host\n'
        'availability, WAN acceptance, or a complete quantum security composition.\n')


def main(expected_head: str, validation_directory: str) -> dict:
    global CREATED_OUT
    require(HEX40.fullmatch(expected_head) is not None and expected_head not in (BASE, FIRST, UPSTREAM, MERGED),
            'expected-head must identify the corrected, successfully tested source')
    require(re.fullmatch(r'integrated-source-\d{2}', validation_directory) is not None
            and int(validation_directory[-2:]) >= 2, 'select an explicit corrected-source validation directory')
    validation_directories = [f'integrated-source-{number:02d}' for number in range(1, int(validation_directory[-2:]) + 1)]
    archives = tuple(validation_directories) + MERGE_ARCHIVES + (FIX_DIRECTORY,)
    require(TASK.resolve() == TASK and REPO.resolve() == REPO and OUT.resolve() == OUT,
            'task paths must be canonical and separate')
    OUT.mkdir(parents=True, exist_ok=False)
    CREATED_OUT = True
    with (OUT / 'driver.py').open('xb') as stream:
        stream.write(read_bytes(Path(__file__).resolve()))
    capture = Capture()
    tree = clean_head(expected_head)
    require(git('remote', 'get-url', 'origin').decode().strip() == ORIGIN, 'unexpected repository origin')
    require(git('show', '-s', '--format=%P', MERGED).decode().split() == [FIRST, UPSTREAM]
            and git('rev-parse', MERGED + '^{tree}').decode().strip() == MERGED_TREE,
            'original integration merge identity differs')
    git('merge-base', '--is-ancestor', MERGED, expected_head)
    outside_before = outside_evidence_tree(expected_head)
    corpus_bytes = read_bytes(REPO / CORPUS)
    corpus = load(REPO / CORPUS)
    require(len(corpus['pinned_blobs']) == 722 and len(corpus['required_paths']) == 641
            and len(corpus['assertions']) == 8 and all(value is False for value in corpus['assertions'].values()),
            'integrated source corpus does not have the reviewed held inventory')
    protected = set(corpus['pinned_blobs']) | set(corpus['required_paths'])
    require(EV_REL + '/README.md' not in protected and EV_REL + '/artifact-index.json' not in protected,
            'mutable evidence metadata unexpectedly source-pinned')
    index = load(EV / 'artifact-index.json')
    validate_index(index)
    original = copy.deepcopy(index)
    require(isinstance(index.get('validated_commits'), list)
            and {'commit': FIRST, 'tree': FIRST_TREE, 'directory': 'committed-source-01', 'command_gates': 28}
            in index['validated_commits']
            and all(row.get('commit') != expected_head for row in index['validated_commits']),
            'original validation identity missing or integrated run already collected')
    original_tracked = {path.decode() for path in git('ls-files', '-z', '--', EV_REL).split(b'\0') if path}
    require(original_tracked == {EV_REL + '/' + name for name in index['files']} | {EV_REL + '/artifact-index.json'},
            'original tracked evidence differs from its exact index')
    for name, expected in index['files'].items():
        check_record(git('show', expected_head + ':' + EV_REL + '/' + name), expected, 'original committed ' + name)
    result = validate_run(expected_head, tree, validation_directory)
    prior_failures = [validate_failed_run(name, expected_head) for name in validation_directories[:-1]]
    supplement = validate_fixture_fix(expected_head, tree, validation_directory)
    first_counts = validate_merge_attempts()
    preflight = json.loads(capture.run('preflight-before-evidence-edits',
                                      ['/bin/bash', 'scripts/project-preflight.sh']).stdout)
    require(isinstance(preflight, dict) and preflight.get('result') == 'PASS',
            'repository preflight did not report PASS before evidence edits')
    capture.run('source-guard-before-collection', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                '--kind', 'head', '--expected-head', expected_head, '--output', str(OUT / 'verified-source-before.json')])
    require(clean_head(expected_head) == tree, 'source changed before evidence copy')
    copied = {name: copy_archive(TASK / 'validation' / name, EV / name, index) for name in archives}
    with (EV / 'first-validation-counts.json').open('xb') as stream:
        stream.write(first_counts)
    with (EV / 'finalize-authority-evidence.py').open('xb') as stream:
        stream.write(read_bytes(Path(__file__).resolve()))
    result['archived_raw_source_inventories'] = copied
    result['first_validation'] = {'commit': FIRST, 'tree': FIRST_TREE, 'command_gates': 28,
                                  'summary_sha256': FIRST_SUMMARY_SHA256, 'count_readback': record(first_counts)}
    result['concurrent_base_commit'] = UPSTREAM
    result['retained_failed_validations'] = prior_failures
    result['supplementary_evidence'] = [supplement]
    changed_since_merge = [name.decode() for name in git('diff', '--name-only', '--no-renames', '-z',
                                                       MERGED, expected_head).split(b'\0') if name]
    require(changed_since_merge, 'corrected tested source has no changes from the failed merge')
    source_patch = git('diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', '--no-renames', MERGED, expected_head)
    with (EV / 'source-correction.patch').open('xb') as stream:
        stream.write(source_patch)
    correction = {'from_commit': MERGED, 'from_tree': MERGED_TREE, 'to_commit': expected_head,
                  'to_tree': tree, 'changed_paths': changed_since_merge,
                  'patch': {'relative_path': 'source-correction.patch', **record(source_patch)}}
    save(EV / 'source-correction.json', correction, fresh=True)
    result['source_correction'] = correction
    save(EV / 'integrated-validation-readback.json', result, fresh=True)
    readme = read_bytes(EV / 'README.md').decode()
    require('## Exact-source validation after concurrent-base integration' not in readme, 'README already finalized')
    (EV / 'README.md').write_text(readme + readme_section(result), encoding='utf-8')
    index['validated_commits'].append({'commit': expected_head, 'tree': tree,
                                       'directory': validation_directory, 'command_gates': result['command_gates']})
    index.setdefault('retained_failed_validations', []).extend(prior_failures)
    index.setdefault('supplementary_evidence', []).append(supplement)
    deleted, newly_compressed = set(), {}
    for name in sorted(inventory(EV, evidence=True)):
        if Path(name).suffix in ('.raw', '.patch'):
            newly_compressed[name + '.gz'] = compress_capture(name, index, protected, deleted, original_tracked)
    rebuild_index(index, original)
    stage(index, deleted, capture, 1)
    checked = capture.run('complete-pr-diff-check-before-final-format',
                          ['/usr/bin/git', '-c', 'core.quotePath=false', 'diff', '--cached', '--check', UPSTREAM],
                          allowed=(0, 2))
    if checked.returncode == 2:
        headers = re.findall(r'^([^\n:]+):(\d+): ([^\n]+)$', checked.stdout.decode(errors='replace'), re.M)
        require(headers and not checked.stderr, 'unrecognized Git whitespace-check failure')
        paths = set()
        for path, _line, reason in headers:
            require(reason in ('trailing whitespace.', 'new blank line at EOF.', 'space before tab in indent.'),
                    'failure is not an archive whitespace condition: ' + reason)
            require(path.startswith(EV_REL + '/'), 'whitespace failure is outside this task evidence: ' + path)
            paths.add(relative(path[len(EV_REL) + 1:]))
        # These raw files are already in the index from stage 1, even if new.
        staged_tracked = original_tracked | {EV_REL + '/' + name for name in index['files']}
        for name in sorted(paths):
            newly_compressed[name + '.gz'] = compress_capture(name, index, protected, deleted, staged_tracked)
        rebuild_index(index, original)
        stage(index, deleted, capture, 2)
    capture.run('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
    capture.run('complete-pr-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check', UPSTREAM])
    changed = {path.decode() for path in git('diff', '--cached', '--name-only', '-z', expected_head).split(b'\0') if path}
    require(changed and all(path.startswith(EV_REL + '/') for path in changed), 'staged source change outside task evidence')
    require(git('rev-parse', 'HEAD').decode().strip() == expected_head
            and git('branch', '--show-current').decode().strip() == BRANCH,
            'HEAD or branch moved during evidence collection')
    require(not git('diff', '--name-only', '-z'), 'unstaged changes remain before final commit')
    require(not git('ls-files', '--others', '--exclude-standard', '-z'),
            'unexpected untracked files remain before final commit')
    require(read_bytes(REPO / CORPUS) == corpus_bytes, 'corpus changed during evidence collection')
    for path in protected:
        if path.startswith(EV_REL + '/'):
            require(git('show', ':' + path) == git('show', expected_head + ':' + path), 'pinned evidence source changed')
    # Every complete source directory is rechecked after copying and compression.
    for name, expected in copied.items():
        require(inventory(TASK / 'validation' / name) == expected, 'original validation directory changed')
    staged_inventory(index)
    save(OUT / 'precommit-readback.json', {'result': 'PASS', 'tested_commit': expected_head, 'tested_tree': tree,
         'outside_evidence_tree_sha256': sha256(outside_before), 'artifact_files': len(index['files']),
         'changed_paths': sorted(changed), 'new_compression': newly_compressed,
         'source_receipts_rewritten': False, 'capture_bytes_trimmed': False})
    preflight = json.loads(capture.run('preflight-before-evidence-commit',
                                      ['/bin/bash', 'scripts/project-preflight.sh', '--staged']).stdout)
    require(isinstance(preflight, dict) and preflight.get('result') == 'PASS',
            'staged repository preflight did not report PASS before evidence commit')
    capture.run('commit-evidence', ['/usr/bin/git', 'commit', '-m', 'test(pq): retain integrated authority validation evidence'])
    head = git('rev-parse', 'HEAD').decode().strip()
    final_tree = clean_head(head)
    require(head != expected_head and git('show', '-s', '--format=%P', head).decode().split() == [expected_head],
            'evidence commit has unexpected ancestry')
    final_changes = {path.decode() for path in git('diff', '--name-only', '-z', expected_head, head).split(b'\0') if path}
    require(final_changes == changed and all(path.startswith(EV_REL + '/') for path in final_changes),
            'final commit changed paths beyond reviewed evidence inventory')
    require(outside_evidence_tree(head) == outside_before and read_bytes(REPO / CORPUS) == corpus_bytes,
            'native, CI, corpus or other source changed in evidence commit')
    require(load(EV / 'artifact-index.json') == index, 'index changed during commit')
    validate_index(index)
    staged_inventory(index)
    capture.run('committed-diff-check', ['/usr/bin/git', 'diff', '--check', expected_head, head])
    capture.run('committed-complete-pr-diff-check', ['/usr/bin/git', 'diff', '--check', UPSTREAM, head])
    capture.run('source-guard-after-collection', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                '--kind', 'head', '--expected-head', head, '--output', str(OUT / 'verified-source-after.json')])
    require(clean_head(head) == final_tree, 'final evidence/source state changed')
    receipt = {'result': 'PASS', 'tested_commit': expected_head, 'tested_tree': tree,
               'evidence_commit': head, 'evidence_tree': final_tree, 'command_gates': result['command_gates'],
               'branch': BRANCH, 'evidence_only': True, 'all_other_source_unchanged': True,
               'artifact_files': len(index['files']), 'archived_directories': list(archives),
               'validation_directory': validation_directory, 'retained_failed_validation_count': len(prior_failures),
               'supplementary_native_checks': 1,
               'new_lossless_compressions': len(newly_compressed), 'original_failed_attempt_preserved': True,
               'source_receipts_rewritten': False, 'capture_bytes_trimmed': False,
               'production_activation': False, 'whole_chain_pq_qualified': False,
               'corpus': record(corpus_bytes), 'artifact_index': record(read_bytes(EV / 'artifact-index.json'))}
    save(OUT / 'receipt.json', receipt, fresh=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--validation-directory', required=True)
    args = parser.parse_args()
    if not HEX40.fullmatch(args.expected_head):
        parser.error('--expected-head must be a complete lowercase Git SHA-1')
    if (re.fullmatch(r'integrated-source-\d{2}', args.validation_directory) is None
            or int(args.validation_directory[-2:]) < 2):
        parser.error('--validation-directory must select integrated-source-02 or a later numbered run')
    try:
        print(json.dumps(main(args.expected_head, args.validation_directory), sort_keys=True), flush=True)
    except Exception as error:
        failure = {'result': 'FAIL', 'expected_head': args.expected_head,
                   'validation_directory': args.validation_directory,
                   'error': f'{type(error).__name__}: {error}', 'production_activation': False,
                   'whole_chain_pq_qualified': False, 'failure_preserved_without_reset': True}
        if CREATED_OUT and OUT.is_dir() and not (OUT / 'receipt.json').exists():
            path = OUT / 'failure.json'
            if not path.exists():
                save(path, failure, fresh=True)
                with (OUT / 'failure-traceback.txt').open('x', encoding='utf-8') as stream:
                    traceback.print_exc(file=stream)
        print(json.dumps(failure, sort_keys=True), file=sys.stderr, flush=True)
        raise SystemExit(1)
