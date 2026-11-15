#!/usr/bin/env python3
"""Repair one stale generated inventory, freeze it, and retain exact-head checks.

This reviewed driver is for the isolated f7e62 checkout only. It never pushes,
changes provider setup, copies smoke keys, or upgrades security qualification.
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
from unittest import mock
import zlib

sys.dont_write_bytecode = True

ROOT = Path('/home/qian-qi/chain-credit-envelope-20261108-f7e62')
OUT = Path('/home/qian-qi/credit-envelope-f7e62-run2')
PRIOR_OUT = Path('/home/qian-qi/credit-envelope-f7e62-run1')
PACKET = Path('/home/qian-qi/credit-envelope-f7e62-transfer-v5.zlib')
PACKET_SHA256 = '5d8d82ce5e5e7cfc1156f2c74c2ea1b32edcc0fcbc977126c995014a1cbe104b'
ORIGINAL_DRIVER_SHA256 = 'ce05862e66ab72bd54f7017283fa987ad86aff41cc1bfee3828b825ed2d2587a'
BASE = '8d5389748873dad6e296d17f2ff20483b5afa5bc'
START = '57511355b9dfb1fc02c90eb0713fd8e95263a662'
BRANCH = 'fix/chain-credit-envelope-20261108-f7e62'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
GENERATOR = 'scripts/refresh_distributed_source_inventory.py'
GENERATOR_BLOB = '5e86bf0b23c2d9d85560659eacf01189f984e807'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
MISSING_PATH = 'trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs'
PROVIDER_SCRIPT = 'scripts/ci/prepare_pq_provider.sh'
PROVIDER_VERSION = '3.5.9'
PROVIDER_ARCHIVE_SHA256 = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
PROVIDER_KEYS = {
    'OPENSSL_DIR', 'OPENSSL_STATIC', 'TRNM_PQ_OPENSSL',
    'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION',
    'OPENSSL_CONF', 'OPENSSL_MODULES',
}
ORIGINAL_STAGE_NAMES = [
    'preflight', 'finite-math', 'candidate-clock', 'restricted-oracle',
    'source-integrity', 'ci-contract', 'repository-negative',
    'project-boundary-negative', 'repository-check', 'inventory-check',
    'cargo-graph', 'cargo-graph-all-features', 'rust-format', 'rust-clippy',
    'retained-native-work',
]
OMITTED_COUNTS = {'repository-negative': 50, 'project-boundary-negative': 16}
UNITTEST_COUNTS = {
    'candidate-clock': 6, 'restricted-oracle': 12,
    'source-integrity': 43, 'ci-contract': 107,
}
EXACT_TESTS = {
    'distributed-source-scope': 'tests::source_scope_and_campaign_bounds_reject',
    'distributed-resume-identity':
        'tests::resume_requires_exact_source_config_identity_and_exclusive_owner',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def checked_file(path: Path, *, max_bytes=None):
    require(path.is_absolute() and path.resolve(strict=True) == path,
            'noncanonical or symlink input path: ' + str(path))
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode), 'not a regular input file: ' + str(path))
    if max_bytes is not None:
        require(before.st_size <= max_bytes, 'input file exceeds bound: ' + str(path))
    data = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns, item.st_mode)
    require(identity(before) == identity(after) and len(data) == before.st_size,
            'input file changed while reading: ' + str(path))
    return data


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse_json(data):
    def reject_constant(value):
        raise ValueError('nonfinite JSON value: ' + value)
    return json.loads(data, object_pairs_hook=no_duplicate_keys,
                      parse_constant=reject_constant)


def read_json(path, *, max_bytes=4 * 1024 * 1024):
    return parse_json(checked_file(path, max_bytes=max_bytes))


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def git_bytes(env, *args):
    return subprocess.check_output(['git', '--no-replace-objects', *args],
                                   cwd=ROOT, env=env)


def git(env, *args):
    return git_bytes(env, *args).decode('utf-8').strip()


def names(raw):
    return [part.decode('utf-8') for part in raw.split(b'\0') if part]


def clean(env):
    require(not git(env, 'status', '--porcelain', '--untracked-files=all',
                    '--ignore-submodules=none'), 'worktree or index is not clean')
    require(not git(env, 'for-each-ref', '--format=%(refname)', 'refs/replace/'),
            'Git replacement refs are not source identity')
    require(not (ROOT / git(env, 'rev-parse', '--git-path', 'info/grafts')).exists(),
            'grafted history is not allowed')
    entries = git_bytes(env, 'ls-files', '-v', '-z').split(b'\0')
    require(not any(row and (row[:1].islower() or row[:1] == b'S') for row in entries),
            'index hides tracked worktree entries')


def selected_provider(provider_dir):
    require(provider_dir.is_absolute() and provider_dir.resolve(strict=True) == provider_dir,
            'provider directory must be canonical and absolute')
    require(provider_dir.is_dir() and provider_dir != ROOT and ROOT not in provider_dir.parents,
            'provider directory must be outside source')
    environment_path = provider_dir / 'github.env'
    receipt_path = provider_dir / 'observations/pq-provider/provider.json'
    raw_environment = checked_file(environment_path, max_bytes=16 * 1024)
    raw_receipt = checked_file(receipt_path, max_bytes=128 * 1024)
    values = {}
    lines = raw_environment.decode('utf-8').splitlines()
    require(len(lines) == 7 and b'\r' not in raw_environment and b'\0' not in raw_environment,
            'provider environment must have exactly seven plain lines')
    for line in lines:
        key, separator, value = line.partition('=')
        require(separator and key in PROVIDER_KEYS and key not in values and value,
                'unexpected, duplicate, or malformed provider environment entry')
        values[key] = value
    require(set(values) == PROVIDER_KEYS, 'provider environment whitelist mismatch')
    receipt = parse_json(raw_receipt)
    require(type(receipt) is dict, 'provider receipt must be an object')
    expected = {
        'schema': 'trnm-ci-pq-provider-v3',
        'result': 'PREPARED_AND_SMOKE_VERIFIED', 'last_stage': 'complete',
        'version': PROVIDER_VERSION,
        'source_archive_sha256_expected': PROVIDER_ARCHIVE_SHA256,
        'source_url': 'https://github.com/openssl/openssl/releases/download/'
                      'openssl-3.5.9/openssl-3.5.9.tar.gz',
        'openssl_conf': '/dev/null',
    }
    for key, value in expected.items():
        require(receipt.get(key) == value, 'provider receipt field mismatch: ' + key)
    require(type(receipt.get('exit_code')) is int and receipt['exit_code'] == 0,
            'provider preparation did not exit zero')
    for key in ('source_digest_verified', 'static_build',
                'ml_dsa_65_sign_verify_and_wrong_message_rejection', 'backend_exported'):
        require(receipt.get(key) is True, 'provider proof is missing: ' + key)
    for key in ('upstream_full_tests_run', 'native_rust_pq_tests_run_by_preparation',
                'independent_cryptographic_implementation_claim',
                'whole_chain_quantum_security_qualified', 'production_activation'):
        require(receipt.get(key) is False, 'provider scope changed: ' + key)
    require(receipt.get('source_transport') in ('download', 'explicit-local-archive'),
            'unrecognized provider source transport')
    build = Path(receipt['build_directory'])
    prefix = Path(receipt['install_prefix'])
    runner_directory = provider_dir / 'runner'
    require(runner_directory.is_dir()
            and runner_directory.resolve(strict=True) == runner_directory,
            'provider runner directory is not canonical')
    require(build.parent == runner_directory and
            re.fullmatch(r'trnm-pq-provider-3\.5\.9\.[A-Za-z0-9]{8}', build.name),
            'provider build is outside the declared isolated directory')
    require(build.resolve(strict=True) == build and prefix == build / 'install'
            and prefix.resolve(strict=True) == prefix,
            'provider install prefix is not canonical')
    require(values['OPENSSL_DIR'] == str(prefix) and values['OPENSSL_STATIC'] == '1'
            and values['TRNM_PQ_OPENSSL'] == str(prefix / 'bin/openssl')
            and values['TRNM_PQ_OPENSSL_VERSION'] == PROVIDER_VERSION
            and values['OPENSSL_CONF'] == '/dev/null'
            and values['OPENSSL_MODULES'] == str(prefix / 'lib/ossl-modules'),
            'provider environment does not match its verified prefix')
    require(receipt.get('cli_executable') == values['TRNM_PQ_OPENSSL']
            and receipt.get('openssl_modules') == values['OPENSSL_MODULES'],
            'provider CLI or module directory differs from environment')
    require(type(receipt.get('cli_version_output')) is str
            and receipt['cli_version_output'].startswith('OpenSSL 3.5.9 '),
            'provider CLI version proof mismatch')
    script_sha = sha256_bytes(checked_file(ROOT / PROVIDER_SCRIPT))
    require(receipt.get('preparation_script_sha256') == script_sha,
            'provider preparation script is not the exact current source')
    archive = build / 'openssl-3.5.9.tar.gz'
    archive_bytes = checked_file(archive)
    require(sha256_bytes(archive_bytes) == PROVIDER_ARCHIVE_SHA256,
            'provider source archive does not match the repository pin')
    relative_files = ('bin/openssl', 'include/openssl/opensslv.h',
                      'include/openssl/configuration.h', 'lib/libcrypto.a', 'lib/libssl.a')
    inputs = receipt.get('native_backend_inputs')
    require(type(inputs) is list and len(inputs) == len(relative_files),
            'provider native artifact inventory is incomplete')
    measured = []
    for row, relative in zip(inputs, relative_files):
        path = prefix / relative
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
                and row['path'] == str(path) and type(row['bytes']) is int,
                'provider native artifact identity is malformed')
        data = checked_file(path)
        identity = {'path': str(path), 'bytes': len(data), 'sha256': sha256_bytes(data)}
        require(identity == row, 'provider artifact bytes differ from smoke receipt: ' + relative)
        measured.append(identity)
    cli_sha = measured[0]['sha256']
    require(receipt.get('cli_sha256') == cli_sha
            and values['TRNM_PQ_OPENSSL_SHA256'] == cli_sha,
            'provider executable digest mismatch')
    return {
        'schema': 'pon-credit-selected-provider-v1', 'provider_directory': str(provider_dir),
        'receipt_path': str(receipt_path), 'receipt_sha256': sha256_bytes(raw_receipt),
        'receipt': receipt, 'github_env_path': str(environment_path),
        'github_env_sha256': sha256_bytes(raw_environment), 'imported_environment': values,
        'verified_native_inputs': measured, 'preparation_script_sha256': script_sha,
        'source_archive': {'path': str(archive), 'bytes': len(archive_bytes),
                           'sha256': PROVIDER_ARCHIVE_SHA256},
        'private_smoke_key_read_or_copied': False,
        'native_rust_pq_tests_claimed_by_this_proof': False,
        'production_activation': False,
    }


def unittest_receipt(contents, expected_count):
    runs = re.findall(r'^Ran ([0-9]+) tests? in .+$', contents, re.M)
    terminal = re.search(
        r'(?:\A|\n)Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s\n\nOK\s*\Z',
        contents)
    require(len(runs) == 1 and terminal is not None and runs[0] == terminal.group(1)
            and int(runs[0]) == expected_count,
            'missing, duplicate, zero, skipped, or wrong-count terminal unittest receipt')
    return expected_count


class Runner:
    def __init__(self, env):
        self.env = env
        self.setup = []
        self.stages = []
        self.head = None
        self.tree = None

    def verify_receipt(self, name, stdout, stderr, evidence):
        if name in UNITTEST_COUNTS:
            evidence['test_methods'] = unittest_receipt(
                stdout + '\n' + stderr, UNITTEST_COUNTS[name])
            evidence['unittest_terminal_receipt_valid'] = True
        if name == 'finite-math':
            completion = read_json(OUT / 'finite-math/completion.json')
            evidence['completion'] = completion
            require(completion.get('schema') == 'pon-credit-envelope-completion-v1'
                    and completion.get('finite_math_checks') == 'PASS'
                    and type(completion.get('distinct_named_tests_passed')) is int
                    and completion['distinct_named_tests_passed'] == 77
                    and completion.get('source_bytes_unchanged') is True
                    and completion.get('overall') == 'HOLD'
                    and completion.get('production_activation') is False,
                    'unexpected finite-math completion')
        if name.startswith('cargo-graph'):
            metadata = parse_json(stdout)
            members = metadata['workspace_members']
            require(type(members) is list and len(members) == len(set(members)) == 26,
                    'workspace package inventory mismatch')
            evidence['workspace_members'] = len(members)
        if name == 'retained-native-work' or name in EXACT_TESTS:
            result_lines = [line for line in stdout.splitlines()
                            if line.startswith('test result:')]
            matches = [re.fullmatch(
                r'test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; '
                r'([0-9]+) measured; ([0-9]+) filtered out; finished in [0-9]+(?:\.[0-9]+)?s',
                line) for line in result_lines]
            require(len(matches) == 1 and matches[0] is not None,
                    'missing or duplicate native test result')
            counts = tuple(int(item) for item in matches[0].groups())
            require(counts[0] > 0 and counts[1:4] == (0, 0, 0)
                    and stdout.rstrip().endswith(result_lines[0]),
                    'unsuccessful or nonterminal native test receipt')
            evidence['native_test_counts'] = {
                'passed': counts[0], 'failed': counts[1], 'ignored': counts[2],
                'measured': counts[3], 'filtered_out': counts[4],
            }
            if name in EXACT_TESTS:
                expected_line = 'test ' + EXACT_TESTS[name] + ' ... ok'
                test_lines = [line for line in stdout.splitlines()
                              if line.startswith('test ') and not line.startswith('test result:')]
                runs = re.findall(r'^running ([0-9]+) tests?$', stdout, re.M)
                require(counts[0] == 1 and runs == ['1'] and test_lines == [expected_line],
                        'exact native test was not executed once and passed')
                evidence['exact_test_name'] = EXACT_TESTS[name]
                evidence['exact_test_line'] = expected_line
        if name in ('source-before', 'source-after'):
            receipt = read_json(OUT / (name + '.json'))
            require(receipt.get('schema') == 'trnm-ci-source-v1'
                    and receipt.get('kind') == 'head'
                    and receipt.get('tested_commit') == self.head
                    and receipt.get('tested_tree') == self.tree
                    and receipt.get('candidate') == self.head
                    and receipt.get('base') is None
                    and receipt.get('prospective_merge') is None
                    and receipt.get('tracked_worktree_verified') is True,
                    'complete-source receipt does not bind the frozen head')
            evidence['source_receipt_sha256'] = sha256_bytes(
                checked_file(OUT / (name + '.json')))

    def run_stage(self, name, argv, timeout=1800, *, setup=False):
        require(re.fullmatch(r'[a-z][a-z0-9-]*', name), 'invalid stage name')
        started, tick = now(), time.monotonic()
        stdout_path, stderr_path = OUT / (name + '.stdout.log'), OUT / (name + '.stderr.log')
        exception = None
        with stdout_path.open('xb') as out_stream, stderr_path.open('xb') as err_stream:
            try:
                process = subprocess.Popen(argv, cwd=ROOT, env=self.env,
                                           stdout=out_stream, stderr=err_stream,
                                           start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    code, exception = 124, 'timeout'
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
            except OSError as error:
                code, exception = 127, type(error).__name__ + ': ' + str(error)
        stdout_bytes, stderr_bytes = stdout_path.read_bytes(), stderr_path.read_bytes()
        evidence = {
            'stage': name, 'argv': argv, 'cwd': str(ROOT), 'started_utc': started,
            'finished_utc': now(), 'elapsed_seconds': round(time.monotonic() - tick, 6),
            'exit_code': code, 'exception': exception,
            'stdout': stdout_path.name, 'stderr': stderr_path.name,
            'stdout_sha256': sha256_bytes(stdout_bytes),
            'stderr_sha256': sha256_bytes(stderr_bytes),
        }
        if code == 0 and not setup:
            try:
                self.verify_receipt(name, stdout_bytes.decode('utf-8'),
                                    stderr_bytes.decode('utf-8'), evidence)
            except Exception as error:
                evidence['validation_error'] = type(error).__name__ + ': ' + str(error)
        evidence['passed'] = code == 0 and 'validation_error' not in evidence
        write_json(OUT / (name + '.stage.json'), evidence)
        (self.setup if setup else self.stages).append(evidence)
        print(json.dumps({key: evidence.get(key) for key in
                          ('stage', 'passed', 'exit_code', 'elapsed_seconds',
                           'test_methods', 'validation_error')}), flush=True)
        return evidence

    def checked_setup(self, name, argv):
        evidence = self.run_stage(name, argv, setup=True)
        require(evidence['passed'], 'required repair setup failed: ' + name)
        return evidence


def load_stages():
    packed = checked_file(PACKET, max_bytes=16 * 1024 * 1024)
    require(sha256_bytes(packed) == PACKET_SHA256, 'original transfer packet hash mismatch')
    payload = parse_json(zlib.decompress(packed))
    require(payload.get('schema') == 'pon-credit-envelope-transfer-v1'
            and payload.get('base_sha') == BASE, 'original transfer packet identity mismatch')
    spec = payload['validation_spec']
    require(spec.get('schema') == 'pon-credit-envelope-validation-spec-v1',
            'original validation spec schema mismatch')
    original = spec['stages']
    require([row[0] for row in original] == ORIGINAL_STAGE_NAMES,
            'original validation stage roster mismatch')
    for name, arguments in original:
        require(type(arguments) is list and arguments
                and all(type(item) is str and '\0' not in item for item in arguments),
                'invalid original stage arguments: ' + name)
    current = [[name, list(arguments)] for name, arguments in original if name not in OMITTED_COUNTS]
    for name, test in EXACT_TESTS.items():
        current.append([name, [
            'cargo', '+1.95.0', 'test', '--offline', '--locked',
            '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
            '--no-default-features', '--example', 'distributed_pipeline', test,
            '--', '--exact', '--test-threads=1',
        ]])
    require(len(current) == len({row[0] for row in current}) == 15,
            'repair validation must retain exactly fifteen distinct stages')
    return original, current


def prior_omitted_evidence(original, env):
    source = read_json(PRIOR_OUT / 'source-commit.json')
    source_tree = git(env, 'rev-parse', START + '^{tree}')
    require(source.get('commit') == START and source.get('base') == BASE
            and source.get('tree') == source_tree,
            'prior observations do not identify the starting source')
    prior_sources = []
    source_bytes = []
    for name in ('source-before', 'source-after'):
        document = checked_file(PRIOR_OUT / (name + '.json'), max_bytes=4 * 1024 * 1024)
        receipt = parse_json(document)
        require(receipt.get('schema') == 'trnm-ci-source-v1'
                and receipt.get('kind') == 'head'
                and receipt.get('tested_commit') == START
                and receipt.get('tested_tree') == source_tree
                and receipt.get('candidate') == START
                and receipt.get('base') is None
                and receipt.get('prospective_merge') is None
                and receipt.get('tracked_worktree_verified') is True,
                'prior complete-source receipt does not bind the starting source')
        stage = read_json(PRIOR_OUT / (name + '.stage.json'))
        expected_argv = [
            'python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
            '--expected-head', START, '--output', str(PRIOR_OUT / (name + '.json')),
        ]
        require(stage.get('stage') == name and stage.get('passed') is True
                and type(stage.get('exit_code')) is int and stage['exit_code'] == 0
                and stage.get('exception') is None and 'validation_error' not in stage
                and stage.get('argv') == expected_argv,
                'prior complete-source stage was not an actual pass')
        for stream in ('stdout', 'stderr'):
            filename = name + '.' + stream + '.log'
            require(stage.get(stream) == filename, 'unexpected prior source raw-log path')
            data = checked_file(PRIOR_OUT / filename)
            require(sha256_bytes(data) == stage.get(stream + '_sha256'),
                    'prior source raw-log digest mismatch: ' + filename)
            if stream == 'stdout':
                require(data == document, 'prior source stdout differs from its retained receipt')
        source_bytes.append(document)
        prior_sources.append({
            'stage': name, 'source_receipt_sha256': sha256_bytes(document),
            'stage_receipt_sha256': sha256_bytes(checked_file(PRIOR_OUT / (name + '.stage.json'))),
            'stdout_sha256': stage['stdout_sha256'], 'stderr_sha256': stage['stderr_sha256'],
        })
    require(source_bytes[0] == source_bytes[1], 'prior complete-source receipts differ')
    result = []
    for name, expected_count in OMITTED_COUNTS.items():
        stage = read_json(PRIOR_OUT / (name + '.stage.json'))
        require(stage.get('stage') == name and stage.get('passed') is True
                and type(stage.get('exit_code')) is int and stage['exit_code'] == 0
                and stage.get('exception') is None and 'validation_error' not in stage
                and stage.get('unittest_terminal_receipt_valid') is True
                and type(stage.get('test_methods')) is int
                and stage['test_methods'] == expected_count
                and stage.get('argv') == dict(original)[name],
                'prior omitted stage was not a verified pass: ' + name)
        raw = []
        for stream in ('stdout', 'stderr'):
            filename = name + '.' + stream + '.log'
            require(stage.get(stream) == filename, 'unexpected prior raw-log path')
            data = checked_file(PRIOR_OUT / filename)
            require(sha256_bytes(data) == stage.get(stream + '_sha256'),
                    'prior raw-log digest mismatch: ' + filename)
            raw.append(data.decode('utf-8'))
        unittest_receipt('\n'.join(raw), expected_count)
        result.append({
            'stage': name, 'historical_source_commit': START, 'historical_source_tree': source_tree,
            'historical_complete_source_receipts': prior_sources,
            'historical_test_methods': expected_count,
            'stage_receipt_sha256': sha256_bytes(checked_file(PRIOR_OUT / (name + '.stage.json'))),
            'rerun_on_repaired_head': False,
            'reason': 'Root selected reuse of prior negative controls; repair only adds one generated native inventory entry.',
            'historical_receipt': stage,
        })
    return result


def repair_inventory(runner, record):
    env = runner.env
    record['phase'] = 'verify-original-inputs'
    changed = names(git_bytes(env, 'diff', '--name-only', '-z', BASE, START))
    sensitive = [path for path in changed if path == 'trillionnium' or path.startswith('trillionnium/')
                 or path == 'config' or path.startswith('config/')
                 or Path(path).name in ('.gitignore', '.ignore', '.rgignore')]
    require(not sensitive, 'native, configuration, or ignore inputs changed since integration base')
    generator_bytes = checked_file(ROOT / GENERATOR)
    require(git(env, 'rev-parse', BASE + ':' + GENERATOR) == GENERATOR_BLOB
            and git(env, 'rev-parse', START + ':' + GENERATOR) == GENERATOR_BLOB
            and generator_bytes == git_bytes(env, 'show', START + ':' + GENERATOR),
            'inventory generator is not the exact unchanged base source')
    tracked = git(env, 'ls-tree', BASE, '--', MISSING_PATH)
    require(re.fullmatch(r'100644 blob [0-9a-f]{40}\t' + re.escape(MISSING_PATH), tracked),
            'the sole omitted source was not a regular file tracked at integration base')
    omitted_blob = git(env, 'rev-parse', BASE + ':' + MISSING_PATH)
    require(git(env, 'rev-parse', START + ':' + MISSING_PATH) == omitted_blob
            and checked_file(ROOT / MISSING_PATH) == git_bytes(env, 'show', START + ':' + MISSING_PATH),
            'the omitted native source changed')
    old = checked_file(ROOT / INVENTORY)
    require(old == git_bytes(env, 'show', BASE + ':' + INVENTORY)
            == git_bytes(env, 'show', START + ':' + INVENTORY),
            'original inventory is not unchanged since integration base')
    require(shutil.which('rg') is not None, 'ripgrep is required to compare both enumeration paths')
    namespace = runpy.run_path(str(ROOT / GENERATOR), run_name='credit_inventory_repair_inspection')
    require(namespace.get('ROOT') == ROOT and namespace.get('OUTPUT') == ROOT / INVENTORY,
            'generator roots changed')
    render = namespace['render']
    rendered = render()
    with mock.patch.object(namespace['shutil'], 'which', return_value=None):
        fallback = render()
    require(type(rendered) is str and rendered == fallback,
            'ripgrep and Git fallback inventory rendering differ')
    expected_addition = [
        '    (\n', f'        "{MISSING_PATH}",\n', '        include_bytes!(concat!(\n',
        '            env!("CARGO_MANIFEST_DIR"),\n', f'            "/../../../{MISSING_PATH}"\n',
        '        )),\n', '    ),\n',
    ]
    old_text = old.decode('utf-8')
    added_block = ''.join(expected_addition)
    require(rendered.count(added_block) == 1
            and rendered.replace(added_block, '', 1) == old_text
            and MISSING_PATH not in old_text,
            'inventory delta is not the sole seven-line pre-existing source entry')
    old_lines, new_lines = old_text.splitlines(keepends=True), rendered.splitlines(keepends=True)
    proposed_diff = ''.join(difflib.unified_diff(
        old_lines, new_lines, fromfile='a/' + INVENTORY, tofile='b/' + INVENTORY))
    with (OUT / 'inventory-proposed.diff').open('x', encoding='utf-8') as stream:
        stream.write(proposed_diff)
    record.update({
        'base_to_start_changed_paths': changed, 'base_to_start_sensitive_changes': sensitive,
        'generator_blob': GENERATOR_BLOB, 'generator_sha256': sha256_bytes(generator_bytes),
        'original_inventory_blob': git(env, 'rev-parse', START + ':' + INVENTORY),
        'original_inventory_sha256': sha256_bytes(old),
        'rendered_inventory_sha256': sha256_bytes(rendered.encode('utf-8')),
        'ripgrep_and_git_render_identical': True, 'omitted_path': MISSING_PATH,
        'omitted_path_base_blob': omitted_blob, 'omitted_path_already_tracked_at_base': True,
        'added_lines': 7, 'removed_lines': 0, 'proposed_diff': 'inventory-proposed.diff',
    })
    write_json(OUT / 'inventory-repair-plan.json', record)
    require(git(env, 'rev-parse', 'HEAD') == START, 'HEAD moved before inventory repair')
    clean(env)
    record['phase'] = 'regenerate-with-original-script'
    runner.checked_setup('repair-generate', ['python3', GENERATOR])
    runner.checked_setup('repair-generator-check', ['python3', GENERATOR, '--check'])
    require(checked_file(ROOT / INVENTORY) == rendered.encode('utf-8')
            and render() == rendered, 'regenerated inventory is not byte-idempotent')
    with mock.patch.object(namespace['shutil'], 'which', return_value=None):
        require(render() == rendered, 'Git enumeration changed after regeneration')
    require(names(git_bytes(env, 'diff', '--name-only', '-z')) == [INVENTORY]
            and not git_bytes(env, 'diff', '--cached', '--name-only', '-z')
            and not git_bytes(env, 'ls-files', '--others', '--exclude-standard', '-z'),
            'inventory generation changed more than the single authorized file')
    require(git(env, 'diff', '--numstat', '--', INVENTORY) == '7\t0\t' + INVENTORY,
            'actual inventory diff is not seven additions and zero deletions')
    actual_diff = git_bytes(env, 'diff', '--no-ext-diff', '--binary', '--', INVENTORY)
    with (OUT / 'inventory-repair.diff').open('xb') as stream:
        stream.write(actual_diff)
    record['actual_diff_sha256'] = sha256_bytes(actual_diff)
    record['actual_diff'] = 'inventory-repair.diff'
    runner.checked_setup('repair-diff-check', ['git', 'diff', '--check'])
    runner.checked_setup('repair-stage-inventory', ['git', 'add', '--', INVENTORY])
    require(names(git_bytes(env, 'diff', '--cached', '--name-only', '-z')) == [INVENTORY]
            and git_bytes(env, 'show', ':' + INVENTORY) == rendered.encode('utf-8'),
            'staged inventory differs from the reviewed rendering')
    runner.checked_setup('repair-staged-preflight', ['bash', 'scripts/project-preflight.sh', '--staged'])
    require(git(env, 'rev-parse', 'HEAD') == START
            and names(git_bytes(env, 'diff', '--cached', '--name-only', '-z')) == [INVENTORY]
            and git_bytes(env, 'show', ':' + INVENTORY) == rendered.encode('utf-8')
            and not git_bytes(env, 'diff', '--name-only', '-z'),
            'source or staged content moved before commit')
    record['phase'] = 'commit-single-generated-inventory'
    runner.checked_setup('repair-commit', [
        'git', '-c', 'user.name=Qian QI',
        '-c', 'user.email=102159240+ProfHepta@users.noreply.github.com',
        'commit', '-m', 'fix(pon): refresh distributed native source inventory',
    ])
    head, tree = git(env, 'rev-parse', 'HEAD'), git(env, 'rev-parse', 'HEAD^{tree}')
    require(re.fullmatch(r'[0-9a-f]{40}', head) and re.fullmatch(r'[0-9a-f]{40}', tree)
            and git(env, 'show', '-s', '--format=%P', head) == START,
            'inventory repair commit has an unexpected identity or parent')
    require(names(git_bytes(env, 'diff', '--name-only', '-z', START, head)) == [INVENTORY]
            and git_bytes(env, 'show', head + ':' + INVENTORY) == rendered.encode('utf-8'),
            'repair commit contains an unexpected source change')
    identity = git(env, 'show', '-s', '--format=%an%x00%ae%x00%cn%x00%ce', head).split('\0')
    require(identity == ['Qian QI', '102159240+ProfHepta@users.noreply.github.com'] * 2,
            'repair commit author or committer differs from authorized identity')
    clean(env)
    runner.head, runner.tree = head, tree
    record.update({'phase': 'committed', 'repair_result': 'PASS', 'source_commit': head,
                   'source_tree': tree, 'repair_parent': START, 'finished_utc': now()})
    write_json(OUT / 'source-commit.json', {'commit': head, 'tree': tree, 'base': BASE,
                                         'repair_parent': START})
    print(json.dumps({'source_commit': head, 'source_tree': tree,
                      'validation_output': str(OUT)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-dir', type=Path, required=True)
    args = parser.parse_args()
    require(ROOT.resolve(strict=True) == ROOT and ROOT.is_dir(), 'unexpected source root')
    require(OUT.parent.resolve(strict=True) == OUT.parent and OUT != ROOT and ROOT not in OUT.parents,
            'observations must be outside the source tree')
    inherited_overrides = {'PYTHONOPTIMIZE', 'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL',
                           'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL'}
    env = {key: value for key, value in os.environ.items()
           if 'OPENSSL' not in key and key not in inherited_overrides}
    env.update({
        'PATH': str(Path.home() / '.cargo/bin') + os.pathsep + env.get('PATH', ''),
        'PYTHONDONTWRITEBYTECODE': '1',
        'CARGO_TARGET_DIR': '/home/qian-qi/credit-envelope-f7e62-cargo-target',
        'CARGO_BUILD_JOBS': '2', 'CARGO_TERM_COLOR': 'never',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
    })
    require(git(env, 'rev-parse', 'HEAD') == START, 'initial HEAD is not the frozen first-run source')
    require(git(env, 'branch', '--show-current') == BRANCH, 'unexpected branch')
    require(git(env, 'remote', 'get-url', 'origin') == ORIGIN, 'unexpected origin')
    require(git(env, 'rev-parse', '--show-toplevel') == str(ROOT), 'unexpected Git worktree')
    clean(env)
    OUT.mkdir(exist_ok=False)
    runner = Runner(env)
    repair = {
        'schema': 'pon-credit-inventory-repair-v1', 'started_utc': now(),
        'integration_base': BASE, 'initial_source_commit': START, 'inventory_path': INVENTORY,
        'repair_result': 'NOT_COMPLETED', 'phase': 'initial-preflight',
        'production_activation': False, 'overall_security_qualification': 'HOLD',
    }
    summary = {
        'schema': 'pon-credit-envelope-runtime-validation-v2', 'integration_base': BASE,
        'repair_parent': START, 'all_stages_passed': False,
        'overall_security_qualification': 'HOLD', 'production_activation': False,
        'source_kind': 'head', 'prospective_merge_executed_here': False,
        'adapted_driver_source_sha256': ORIGINAL_DRIVER_SHA256,
        'repair_driver_sha256': sha256_bytes(checked_file(Path(__file__).resolve())),
        'original_packet_sha256': PACKET_SHA256, 'prior_output_unmodified': str(PRIOR_OUT),
    }
    try:
        runner.checked_setup('repair-initial-preflight', ['bash', 'scripts/project-preflight.sh'])
        provider = selected_provider(args.provider_dir)
        env.update(provider['imported_environment'])
        write_json(OUT / 'selected-provider.json', provider)
        original, current = load_stages()
        omitted = prior_omitted_evidence(original, env)
        write_json(OUT / 'validation-spec.json', {
            'schema': 'pon-credit-envelope-repair-validation-spec-v1',
            'original_stages': original, 'current_stages': current,
            'historical_stages_not_rerun_here': omitted,
        })
        repair_inventory(runner, repair)
        head, tree = runner.head, runner.tree
        summary.update({'source_commit': head, 'source_tree': tree,
                        'historical_stages_not_rerun_here': omitted})
        before = runner.run_stage('source-before', [
            'python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
            '--expected-head', head, '--output', str(OUT / 'source-before.json'),
        ])
        # Stage failures, including malformed receipts, never skip the remaining stages.
        for name, arguments in current:
            runner.run_stage(name, [arg.replace('@OUT@', str(OUT)) for arg in arguments])
        after = runner.run_stage('source-after', [
            'python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
            '--expected-head', head, '--output', str(OUT / 'source-after.json'),
        ])
        identical = (before['passed'] and after['passed']
                     and checked_file(OUT / 'source-before.json') == checked_file(OUT / 'source-after.json'))
        provider_after = selected_provider(args.provider_dir)
        write_json(OUT / 'selected-provider-after.json', provider_after)
        provider_unchanged = provider_after == provider
        expected_stage_names = ['source-before'] + [row[0] for row in current] + ['source-after']
        roster_complete = [stage['stage'] for stage in runner.stages] == expected_stage_names
        summary.update({
            'expected_stage_names': expected_stage_names, 'stage_roster_complete': roster_complete,
            'complete_source_receipts_identical': identical,
            'selected_provider_unchanged': provider_unchanged,
            'selected_provider_receipt_sha256': sha256_bytes(checked_file(OUT / 'selected-provider.json')),
            'all_stages_passed': identical and provider_unchanged and roster_complete
                                 and len(runner.stages) == 17
                                 and all(stage['passed'] for stage in runner.stages),
        })
    except Exception as error:
        summary['driver_error'] = type(error).__name__ + ': ' + str(error)
        summary['all_stages_passed'] = False
        repair['failure_phase'] = repair.get('phase')
        if repair.get('repair_result') != 'PASS':
            repair['repair_result'] = 'FAILED'
        write_json(OUT / 'driver-error.json', {
            'error': summary['driver_error'], 'traceback': traceback.format_exc(),
            'phase': repair.get('phase'), 'source_commit': runner.head,
        })
    summary.update({'finished_utc': now(), 'setup_commands': runner.setup, 'stages': runner.stages})
    repair['finished_utc'] = now()
    write_json(OUT / 'inventory-repair.json', repair)
    write_json(OUT / 'validation-summary.json', summary)
    print(json.dumps({'validation_complete': len(runner.stages) == 17,
                      'source_commit': runner.head, 'all_stages_passed': summary['all_stages_passed'],
                      'overall': 'HOLD', 'driver_error': summary.get('driver_error')}), flush=True)
    return 0 if summary['all_stages_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
