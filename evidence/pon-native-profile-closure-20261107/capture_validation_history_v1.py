#!/usr/bin/env python3
"""Read-only collection of a terminal 33-gate run, including failed runs.

Only --out and --archive are created. No validator or captured executable is
executed, and SQLite is copied as bytes without opening/recovering a database.
The source summary's status is retained independently of the derived review.
Exit 0 means the archive passed byte readback, NOT that validation passed.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile


LABELS = (
    'preflight', 'cargo-version', 'rustc-version', 'openssl-version',
    'locked-workspace-graph', 'locked-fuzz-graph', 'format', 'native-build',
    'fresh-native-build', 'authority-native-build', 'grouped-python-and-native',
    'conditional-query-bound', 'fresh-query-floor', 'fresh-resource-transfer',
    'native-crypto-all-targets', 'native-header-binding', 'native-fresh-admission',
    'native-verification-authority', 'source-integrity-controls',
    'ci-contract-controls', 'source-inventory', 'repository-and-links',
    'strict-workspace-clippy', 'whitespace', 'native-task-core-all-targets',
    'native-funded-service-contract', 'native-active-anchor',
    'native-demand-evidence', 'native-task-operation-v2', 'native-no-gain-fees',
    'demand-evidence-python', 'upgrade-policy-python',
    'pq-research-integration-controls',
)
DRIVER = 'formal/pon-nakamoto-v1/experiments/validate_grouped_profile_closure_v1.py'
ORIGINAL_DRIVER = 'formal/pon-nakamoto-v1/experiments/validate_grouped_fresh_work_v0.py'
ORIGINAL_DRIVER_SHA = 'f32c38ce97270511783051b48b1249c7ce0e93af0c4e728077cdddfaeef64b64'
RETENTION_SCHEMA = 'pon-grouped-query-retained-native-failure-v1'
CAPTURE_SCHEMA = 'pon-grouped-query-native-capture-test-v1'
PAID_SCHEMA = 'pon-native-task-current-fixture-observation-v1'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
            size += len(chunk)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key: ' + key)
        value[key] = item
    return value


def reject_constant(value):
    raise ValueError('nonfinite JSON: ' + value)


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save_json(path, value):
    save(path, (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                          allow_nan=False) + '\n').encode())


def safe_relative(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('invalid relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(piece in ('', '.', '..') for piece in value.split('/')):
        raise ValueError('unsafe relative path: ' + value)
    return Path(*path.parts)


def no_symlinks(path, *, must_exist=True):
    if not path.is_absolute():
        raise ValueError('absolute path required: ' + str(path))
    if '..' in path.parts:
        raise ValueError('parent path forbidden: ' + str(path))
    for part in [*reversed(path.parents), path]:
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            if must_exist:
                raise
            continue
        if stat.S_ISLNK(mode):
            raise ValueError('symlink forbidden: ' + str(part))
    return path


class Collector:
    def __init__(self, args):
        self.root = no_symlinks(args.root.absolute())
        self.validation = no_symlinks(args.validation.absolute())
        self.out = no_symlinks(args.out.absolute(), must_exist=False)
        self.archive = no_symlinks(args.archive.absolute(), must_exist=False)
        if not self.root.is_dir() or not self.validation.is_dir():
            raise ValueError('root and validation must be existing directories')
        if self.root not in self.validation.parents:
            raise ValueError('validation must be below root')
        if (self.out == self.validation or self.validation in self.out.parents
                or self.out in self.validation.parents):
            raise ValueError('output and input directories must be disjoint')
        if self.out == self.archive or self.out in self.archive.parents:
            raise ValueError('archive must be outside output directory')
        if self.archive == self.validation or self.validation in self.archive.parents:
            raise ValueError('archive must be outside validation input')
        if self.out.exists() or self.archive.exists():
            raise FileExistsError('output directory and archive must both be new')
        self.out.mkdir(parents=True, exist_ok=False)
        self.issues = []
        self.files = {}
        self.trees = {}

    def issue(self, code, **details):
        self.issues.append(dict(code=code, **details))

    def check(self, condition, code, **details):
        if not condition:
            self.issue(code, **details)
        return bool(condition)

    def copy_tree(self, source, relative):
        """Retain every regular file; reject links, special files and changes."""
        source = no_symlinks(source)
        if not source.is_dir():
            raise ValueError('not a directory: ' + str(source))
        before = {}
        for directory, dirs, names in os.walk(source, followlinks=False):
            base = Path(directory)
            for name in list(dirs):
                path = base / name
                if not stat.S_ISDIR(path.lstat().st_mode):
                    dirs.remove(name)
                    self.issue('UNSAFE_DIRECTORY_NOT_COPIED', path=str(path))
            for name in sorted(names):
                path = base / name
                rel = path.relative_to(source).as_posix()
                try:
                    initial = path.lstat()
                    if not stat.S_ISREG(initial.st_mode):
                        raise ValueError('not a regular file')
                    target = self.out / relative / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    digest = hashlib.sha256()
                    size = 0
                    with os.fdopen(fd, 'rb') as inp, target.open('xb') as output:
                        opened = os.fstat(inp.fileno())
                        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
                            raise ValueError('file changed before open')
                        for chunk in iter(lambda: inp.read(1024 * 1024), b''):
                            output.write(chunk)
                            digest.update(chunk)
                            size += len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                        after = os.fstat(inp.fileno())
                    key = (Path(relative) / rel).as_posix()
                    self.files[key] = {'path': key, 'bytes': size, 'sha256': digest.hexdigest()}
                    before[rel] = (initial.st_dev, initial.st_ino, initial.st_size,
                                   initial.st_mtime_ns, initial.st_ctime_ns)
                    end = path.lstat()
                    for current in (opened, after, end):
                        self.check((current.st_dev, current.st_ino, current.st_size,
                                    current.st_mtime_ns, current.st_ctime_ns) == before[rel],
                                   'SOURCE_CHANGED_DURING_COPY', path=str(path))
                    self.check(size == initial.st_size, 'COPIED_SIZE_CHANGED', path=str(path))
                except (OSError, ValueError) as error:
                    self.issue('SOURCE_FILE_COPY_FAILED', path=str(path), error=str(error))
        later = {}
        for directory, dirs, names in os.walk(source, followlinks=False):
            for name in names:
                path = Path(directory) / name
                try:
                    info = path.lstat()
                    later[path.relative_to(source).as_posix()] = (
                        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                except OSError as error:
                    self.issue('SOURCE_CHANGED_AFTER_COPY', path=str(path), error=str(error))
        self.check(before == later, 'SOURCE_TREE_CHANGED_OR_NOT_FULLY_COPIED', path=str(source))
        result = {'source': str(source), 'archive_directory': str(relative),
                  'files': [self.files[(Path(relative) / name).as_posix()]
                            for name in sorted(before)]}
        self.trees[str(source)] = result
        return result

    def read_json(self, relative, default=None):
        try:
            return parse((self.out / 'validation' / relative).read_bytes())
        except (OSError, ValueError) as error:
            self.issue('JSON_UNAVAILABLE_OR_INVALID', path=relative, error=str(error))
            return default

    def json_log(self, label):
        path = self.out / 'validation' / (label + '.log')
        decoder = json.JSONDecoder(object_pairs_hook=unique, parse_constant=reject_constant)
        rows = []
        if not path.is_file():
            return rows
        with path.open(encoding='utf-8', errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                position = line.find('{')
                if position < 0:
                    continue
                try:
                    row, _ = decoder.raw_decode(line[position:])
                except ValueError as error:
                    if ('pon-grouped-query-' in line or 'NATIVE_TASK_CURRENT_V3_OBSERVATION' in line):
                        self.issue('MALFORMED_CAPTURE_JSON', log=path.name, line=number, error=str(error))
                    continue
                if isinstance(row, dict):
                    rows.append((number, row))
        return rows

    def test_summaries(self, label):
        path = self.out / 'validation' / (label + '.log')
        result = {'python': {'ran': [], 'outcomes': [], 'fatal_skip_lines': [],
                             'skip_lines': [], 'failure_lines': []},
                  'rust': {'results': [], 'totals': {}}, 'fatal_lines': []}
        if not path.is_file():
            return result
        rust = re.compile(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; '
                          r'(\d+) ignored; (\d+) measured; (\d+) filtered out;(.*)$')
        ran = re.compile(r'^Ran (\d+) tests? in (.+)$')
        fields = ('passed', 'failed', 'ignored', 'measured', 'filtered_out')
        with path.open(encoding='utf-8', errors='replace') as stream:
            for number, raw in enumerate(stream, 1):
                line = raw.strip()
                item = {'line': number, 'text': line}
                match = rust.match(line)
                if match:
                    result['rust']['results'].append(dict(item, status=match[1], **{
                        key: int(match[index + 2]) for index, key in enumerate(fields)}))
                match = ran.match(line)
                if match:
                    result['python']['ran'].append(dict(item, tests=int(match[1])))
                if re.match(r'^(OK|FAILED)(\s|\(|$)', line):
                    result['python']['outcomes'].append(item)
                if re.search(r'\bFATAL\b.*\bskip', line, re.I):
                    result['python']['fatal_skip_lines'].append(item)
                if (line.startswith('test') and re.search(r'\.\.\.\s+skipped\b', line)) or re.match(r'^(OK|FAILED).*skipped=', line):
                    result['python']['skip_lines'].append(item)
                if re.match(r'^(FAIL:|ERROR:|FAILED\b)', line):
                    result['python']['failure_lines'].append(item)
                if re.match(r'^(FATAL\b|error:|error\[|thread .*panicked)', line, re.I):
                    result['fatal_lines'].append(item)
        result['rust']['totals'] = {key: sum(row[key] for row in result['rust']['results']) for key in fields}
        result['rust']['result_lines'] = len(result['rust']['results'])
        result['python']['tests_reported_in_ran_lines'] = sum(row['tests'] for row in result['python']['ran'])
        result['python']['ok_lines'] = sum(row['text'].startswith('OK') for row in result['python']['outcomes'])
        result['python']['failed_lines'] = sum(row['text'].startswith('FAILED') for row in result['python']['outcomes'])
        return result

    def validation_review(self):
        summary = self.read_json('summary.json', {})
        plan = self.read_json('plan.json', {})
        records = self.read_json('commands.json', [])
        before = self.read_json('source-before.json', {})
        after = self.read_json('source-after.json', {})
        binding = self.read_json('runner-bindings.json', {})
        drivers = self.read_json('driver-bindings.json', {})
        if not all(isinstance(row, dict) for row in (summary, plan, before, after, binding, drivers)):
            self.issue('VALIDATION_OBJECT_TYPES')
            summary, plan, before, after, binding, drivers = [row if isinstance(row, dict) else {} for row in (summary, plan, before, after, binding, drivers)]
        if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
            self.issue('COMMAND_RECORD_TYPES')
            records = []
        planned = plan.get('commands', [])
        if not isinstance(planned, list) or any(not isinstance(row, dict) for row in planned):
            planned = []
            self.issue('PLAN_COMMAND_TYPES')
        self.check(tuple(row.get('label') for row in planned) == LABELS, 'PLAN_33_COMMAND_INVENTORY')
        self.check(tuple(row.get('label') for row in records) == LABELS, 'RECORDED_33_COMMAND_INVENTORY')
        self.check(plan.get('planned_commands') == 33 and summary.get('commands_planned') == 33
                   and summary.get('commands_recorded') == len(records)
                   and summary.get('complete_command_denominator') is True
                   and summary.get('unchanged_prefix_commands') == 24
                   and summary.get('additional_owner_relation_commands') == 9,
                   'COMMAND_DENOMINATOR_FIELDS')
        try:
            ledger = [parse(line) for line in (self.out / 'validation/commands.ndjson').read_bytes().splitlines() if line.strip()]
            self.check(ledger == records, 'COMMAND_LEDGER_DIFFERS')
        except (OSError, ValueError) as error:
            self.issue('COMMAND_LEDGER_UNAVAILABLE', error=str(error))
        command_reviews = []
        for index, record in enumerate(records):
            label = record.get('label')
            if label not in LABELS:
                self.issue('UNKNOWN_COMMAND_LABEL', label=label)
                continue
            expected = planned[index] if index < len(planned) else {}
            hashed = {key: value for key, value in expected.items() if key != 'command_sha256'}
            self.check(expected.get('command_sha256') == sha(canonical(hashed)), 'COMMAND_DIGEST_DIFFERS', label=label)
            self.check(record.get('ordinal') == index + 1 and all(record.get(key) == value for key, value in expected.items()),
                       'COMMAND_PLAN_DIFFERS', label=label)
            self.check(self.read_json(label + '.result.json') == record, 'PER_COMMAND_RECORD_DIFFERS', label=label)
            status = record.get('status')
            self.check(status in ('PASS', 'FAIL', 'NOT_STARTED'), 'UNKNOWN_COMMAND_STATUS', label=label, status=status)
            log_verified = False
            if record.get('log') is not None:
                self.check(record.get('log') == label + '.log', 'UNEXPECTED_LOG_PATH', label=label)
                meta = self.files.get('validation/' + label + '.log')
                log_verified = bool(meta and meta['bytes'] == record.get('log_bytes') and meta['sha256'] == record.get('log_sha256'))
                self.check(log_verified, 'ORIGINAL_LOG_DIGEST_DIFFERS_OR_MISSING', label=label)
            else:
                self.check(status == 'NOT_STARTED' and record.get('log_bytes') is None and record.get('log_sha256') is None,
                           'STARTED_COMMAND_WITHOUT_LOG', label=label)
            if status == 'PASS':
                self.check(record.get('exit_code') == 0 and record.get('process_started') is True
                           and record.get('timed_out') is False and not record.get('interrupted')
                           and 'error' not in record and 'cleanup_error' not in record and log_verified,
                           'PASS_COMMAND_INCONSISTENT', label=label)
            command_reviews.append({'ordinal': record.get('ordinal'), 'label': label,
                'status': status, 'exit_code': record.get('exit_code'),
                'timed_out': record.get('timed_out'), 'process_started': record.get('process_started'),
                'reason': record.get('reason'), 'log_sha256_verified': log_verified,
                'test_summaries': self.test_summaries(label)})
        counts = collections.Counter(row.get('status') for row in records)
        for field, value in [('commands_passed', counts['PASS']), ('commands_failed', counts['FAIL']),
                             ('commands_not_started', counts['NOT_STARTED']),
                             ('commands_timed_out', sum(row.get('timed_out') is True for row in records))]:
            self.check(summary.get(field) == value, 'SUMMARY_COMMAND_COUNT_DIFFERS', field=field, observed=value)
        source = summary.get('expected_source_sha')
        self.check(isinstance(source, str) and HEX40.fullmatch(source) is not None and plan.get('expected_source_sha') == source,
                   'EXPECTED_SOURCE_IDENTITY')
        source_before = before.get('source') or {}
        source_after = after.get('source') or {}
        source_gate = (before.get('status') == after.get('status') == 'PASS'
            and isinstance(source_before, dict) and source_before == source_after == summary.get('source')
            and source_before.get('schema') == 'trnm-ci-source-v1'
            and source_before.get('kind') == 'head'
            and source_before.get('tested_commit') == source_before.get('candidate') == source
            and source_before.get('tracked_worktree_verified') is True
            and type(source_before.get('tracked_entries')) is int and source_before['tracked_entries'] > 0
            and type(source_before.get('tracked_bytes')) is int and source_before['tracked_bytes'] > 0
            and isinstance(source_before.get('tested_tree'), str) and HEX40.fullmatch(source_before['tested_tree']) is not None
            and summary.get('source_failures') == [])
        self.check(source_gate, 'RECORDED_EXACT_SOURCE_GATE_NOT_COMPLETE')
        self.check(before.get('drivers') == after.get('drivers') == drivers and bool(drivers)
                   and all(summary.get(key) == value and plan.get(key) == value for key, value in drivers.items())
                   and drivers.get('original_driver_sha256') == drivers.get('loaded_original_driver_sha256')
                   == drivers.get('frozen_original_driver_sha256') == ORIGINAL_DRIVER_SHA
                   and drivers.get('driver_sha256') == drivers.get('loaded_driver_sha256'),
                   'EXECUTING_DRIVER_BINDINGS_DIFFER')
        self.check(summary.get('runner_bindings') == binding, 'RUNNER_BINDING_SUMMARY_DIFFERS')
        self.check(binding.get('status') == 'PASS', 'RECORDED_RUNNER_BINDINGS_NOT_PASS')
        for name, build, field in [('grouped', 'native-build', 'native_runner_sha256'),
                                    ('fresh', 'fresh-native-build', 'fresh_native_runner_sha256'),
                                    ('authority', 'authority-native-build', 'authority_native_runner_sha256')]:
            artifact = binding.get('artifacts', {}).get(name, {})
            built = [row for row in records if row.get('label') == build]
            self.check(len(built) == 1 and built[0].get('status') == 'PASS'
                       and built[0].get('built_runner') == artifact and artifact.get('exists') is True
                       and artifact.get('executable') is True and isinstance(artifact.get('sha256'), str)
                       and HEX64.fullmatch(artifact['sha256']) is not None
                       and summary.get(field) == artifact.get('sha256'), 'RUNNER_BUILD_BINDING_DIFFERS', runner=name)
        source_files = []
        repo = Path(plan.get('repository', ''))
        try:
            no_symlinks(repo)
            if repo != self.root / 'repo' or not isinstance(source, str) or HEX40.fullmatch(source) is None:
                raise ValueError('repository or source identity outside allowed scope')
            for relative in (DRIVER, ORIGINAL_DRIVER, 'scripts/ci/verify_ci_source.py'):
                result = subprocess.run(['git', '--no-replace-objects', 'show', source + ':' + relative],
                    cwd=repo, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=60, check=False)
                if result.returncode:
                    raise ValueError('git show failed for ' + relative + ': ' + result.stderr.decode(errors='replace'))
                save(self.out / 'committed-source-guards' / relative, result.stdout)
                meta = {'path': relative, 'bytes': len(result.stdout), 'sha256': sha(result.stdout), 'commit': source}
                source_files.append(meta)
                if relative in (DRIVER, ORIGINAL_DRIVER):
                    key = 'driver_sha256' if relative == DRIVER else 'original_driver_sha256'
                    self.check(meta['sha256'] == drivers.get(key), 'COMMITTED_DRIVER_BYTES_DIFFER', path=relative)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.issue('COMMITTED_SOURCE_GUARDS_NOT_RETAINED', error=str(error))
        return summary, {'plan': plan, 'source_before': before, 'source_after': after,
            'recorded_source_gate_complete': source_gate, 'driver_bindings': drivers,
            'committed_source_guards': source_files, 'runner_bindings': binding,
            'commands': command_reviews, 'command_counts': dict(counts)}

    def fixture_path(self, value):
        if not isinstance(value, str):
            raise ValueError('fixture directory must be a string')
        path = no_symlinks(Path(value))
        if path.parent != self.root / 'tmp' or re.fullmatch(r'pon-query-observer-v1-[A-Za-z0-9_-]+', path.name) is None:
            raise ValueError('fixture path outside ROOT/tmp direct child namespace: ' + value)
        return path

    def capture_review(self, summary):
        rows = self.json_log('grouped-python-and-native')
        captures, readers, retentions, process_rows, fixtures = [], [], [], [], {}
        expected_source = summary.get('expected_source_sha')
        expected_runner = summary.get('authority_native_runner_sha256')
        for line, row in rows:
            schema = row.get('schema')
            if isinstance(schema, str) and schema.startswith('pon-grouped-query-native-') and 'source_commit' in row:
                self.check(row.get('source_commit') == expected_source and row.get('runner_sha256') == expected_runner,
                           'NATIVE_CAPTURE_SOURCE_BINDING', line=line, schema=schema)
            if schema == CAPTURE_SCHEMA:
                errors_before = len(self.issues)
                prefix = row.get('durable_prefix')
                if not isinstance(prefix, list) or any(not isinstance(item, dict) for item in prefix):
                    self.issue('QUERY_PREFIX_TYPE', line=line)
                    prefix = []
                raw = b''.join(canonical(item) + b'\n' for item in prefix)
                self.check(sha(raw) == row.get('durable_prefix_sha256'), 'QUERY_PREFIX_DIGEST_DIFFERS', line=line)
                self.check(len(prefix) <= 65 and [item.get('ordinal') for item in prefix] == list(range(len(prefix))),
                           'QUERY_PREFIX_ORDINALS_OR_BOUND', line=line)
                seeds = sum(item.get('kind') == 'seed' for item in prefix)
                steps = sum(item.get('kind') == 'step' for item in prefix)
                for item in prefix:
                    try:
                        answer = hashlib.sha256(bytes.fromhex(item['input_hex'])).hexdigest()
                        self.check(answer == item.get('answer'), 'OBSERVED_QUERY_ANSWER_DIFFERS', line=line, ordinal=item.get('ordinal'))
                    except (KeyError, TypeError, ValueError) as error:
                        self.issue('OBSERVED_QUERY_ENCODING_INVALID', line=line, error=str(error))
                report = row.get('native_response')
                if isinstance(report, dict):
                    self.check(sha(canonical(report)) == row.get('native_response_sha256'), 'NATIVE_RESPONSE_DIGEST_DIFFERS', line=line)
                    self.check(report.get('query_observations') == prefix and report.get('observed_seed_queries') == seeds
                               and report.get('observed_step_queries') == steps, 'NATIVE_RESPONSE_PREFIX_DIFFERS', line=line)
                    self.check(report.get('source_commit') == expected_source and report.get('runner_sha256') == expected_runner
                               and report.get('request_sha256') == sha(canonical(row.get('request'))), 'NATIVE_RESPONSE_BINDING_DIFFERS', line=line)
                    self.check(report.get('chainwork_awarded') == 0 and report.get('production_activation') is False
                               and report.get('public_query_coverage_complete') is False
                               and report.get('historical_trace_reconstructed') is False, 'NATIVE_RESPONSE_SCOPE_CHANGED', line=line)
                else:
                    self.check(report is None and row.get('process_returncode') != 0,
                               'MISSING_SUCCESSFUL_NATIVE_RESPONSE', line=line)
                    self.check(row.get('native_response_sha256') in (None, sha(b'')), 'INTERRUPTED_RESPONSE_DIGEST_DIFFERS', line=line)
                captures.append({'original_log_line': line, 'case': row.get('case'), 'label': row.get('label'),
                    'process_returncode': row.get('process_returncode'), 'seed_queries': seeds, 'step_queries': steps,
                    'durable_prefix_sha256': row.get('durable_prefix_sha256'),
                    'native_response_sha256': row.get('native_response_sha256'),
                    'capture_checks_passed': len(self.issues) == errors_before})
            elif schema == 'pon-grouped-query-native-reader-test-v1':
                readers.append({'original_log_line': line, 'capture': row})
            elif schema in ('pon-grouped-query-native-process-test-v1', 'pon-grouped-query-native-timeout-test-v1',
                            'pon-grouped-query-native-malformed-capture-test-v1'):
                process_rows.append({'original_log_line': line, 'capture': row})
            if schema == 'pon-grouped-query-retained-directory-v1':
                try:
                    path = self.fixture_path(row.get('directory'))
                    fixtures[str(path)] = path
                except (OSError, ValueError) as error:
                    self.issue('RETAINED_ORIGINAL_PATH_INVALID', line=line, error=str(error))
            manifest = row.get('manifest')
            if not isinstance(manifest, dict) or manifest.get('schema') != RETENTION_SCHEMA:
                continue
            retained_review = {'original_log_line': line, 'manifest': manifest, 'verified': False}
            retentions.append(retained_review)
            # Register each available directory separately: a missing original
            # must not prevent retention of the still-present STARTED snapshot.
            available = {}
            for field in ('retained_directory', 'original_directory'):
                try:
                    path = self.fixture_path(manifest.get(field))
                    available[field] = path
                    fixtures[str(path)] = path
                except (OSError, ValueError) as error:
                    self.issue('RETENTION_DIRECTORY_MISSING_OR_UNSAFE', line=line, field=field, error=str(error))
            try:
                retained = available['retained_directory']
                original = available['original_directory']
                if not retained.name.startswith(original.name + '-retained-'):
                    raise ValueError('retained directory not bound to original directory name')
                if parse(no_symlinks(retained / 'RETENTION_MANIFEST.json').read_bytes()) != manifest:
                    raise ValueError('retained manifest bytes decode differently from logged manifest')
                self.check(manifest.get('source_commit') == expected_source and manifest.get('runner_sha256') == expected_runner,
                           'RETENTION_SOURCE_BINDING', line=line)
                self.check(manifest.get('captured_before_next_owner_open') is True,
                           'RETENTION_NOT_BEFORE_REOPEN', line=line)
                declared = {}
                for item in manifest.get('files', []):
                    rel = safe_relative(item['path'])
                    if rel.as_posix() in declared:
                        raise ValueError('duplicate retained file path')
                    path = no_symlinks(retained / rel)
                    if not path.is_file():
                        raise ValueError('retained file is missing')
                    meta = file_digest(path)
                    if meta != {'bytes': item.get('bytes'), 'sha256': item.get('sha256')}:
                        raise ValueError('retained bytes/hash differ: ' + str(rel))
                    declared[rel.as_posix()] = meta
                actual = {path.relative_to(retained).as_posix() for path in retained.rglob('*') if path.is_file()}
                if actual != set(declared) | {'RETENTION_MANIFEST.json'}:
                    raise ValueError('retained file denominator differs')
                for raw_capture in row.get('raw_query_and_response_captures', []):
                    rel = safe_relative(raw_capture['path']).as_posix()
                    raw = bytes.fromhex(raw_capture['raw_hex'])
                    if (declared.get(rel) != {'bytes': len(raw), 'sha256': sha(raw)}
                            or len(raw) != raw_capture.get('bytes') or sha(raw) != raw_capture.get('sha256')):
                        raise ValueError('inline retained capture differs from original bytes')
                retained_review['verified'] = True
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.issue('RETENTION_VERIFICATION_FAILED', line=line, error=str(error))
        copied = []
        for name, source in sorted(fixtures.items()):
            try:
                # These fixtures reached execute. Their current primary owner
                # stores must still exist, even though reopening may have
                # legitimately changed STARTED to UNKNOWN and removed sidecars.
                # Node::open treats native-node.sqlite as a directory; the
                # actual primary SQLite file is its native.sqlite child.
                required = ('config.json', 'owner/authority.sqlite', 'owner/native-node.sqlite/native.sqlite',
                            'owner/config.json', 'owner/preparation.json', 'owner/capsule.bin')
                for relative in required:
                    path = source / relative
                    try:
                        no_symlinks(path)
                        self.check(stat.S_ISREG(path.lstat().st_mode), 'PRIMARY_FIXTURE_FILE_MISSING_OR_UNSAFE',
                                   directory=name, path=relative)
                    except (OSError, ValueError) as error:
                        self.issue('PRIMARY_FIXTURE_FILE_MISSING_OR_UNSAFE', directory=name,
                                   path=relative, error=str(error))
                copied.append(self.copy_tree(source, Path('original-fixtures') / source.name))
            except (OSError, ValueError) as error:
                self.issue('FIXTURE_DIRECTORY_COPY_FAILED', path=name, error=str(error))
        paid = [{'original_log_line': line, 'capture': row} for line, row in self.json_log('native-task-operation-v2') if row.get('schema') == PAID_SCHEMA]
        self.check(len(paid) == 12, 'CURRENT_PAID_CAPTURE_DENOMINATOR', actual=len(paid), expected=12)
        labels = ('complete', 'cancel-0', 'cancel-17', 'cancel-64', 'first', 'cached',
                  'interrupted', 'reconciled', 'forged', 'framing', 'retained', 'after-refused-overwrite')
        self.check(collections.Counter(row['label'] for row in captures) == collections.Counter(labels)
                   and len({row['case'] for row in captures}) == 7,
                   'NATIVE_QUERY_CONTROL_CAPTURE_DENOMINATOR', actual=len(captures), expected=12)
        self.check(len(retentions) >= 2, 'NATIVE_RETENTION_CAPTURE_DENOMINATOR', actual=len(retentions), minimum=2)
        phases = collections.Counter(row['capture'].get('phase') for row in paid)
        backends = collections.Counter(row['capture'].get('backend') for row in paid)
        self.check(phases == {'original-paid': 10, 'same-operations-reappeared-paid-at-dispute-boundary': 2}
                   and backends == {'legacy': 6, 'authenticated-v1': 6}, 'CURRENT_PAID_CAPTURE_PHASES_OR_BACKENDS')
        for row in paid:
            self.check(row['capture'].get('evidence_kind') == 'CONTROLLED_FIXTURE', 'CURRENT_PAID_CAPTURE_SCOPE', line=row['original_log_line'])
        return {'query_capture_count': len(captures), 'query_captures': captures,
            'query_schema_counts': dict(collections.Counter(row.get('schema', 'retention_wrapper') for _, row in rows
                if str(row.get('schema', '')).startswith('pon-grouped-query-') or isinstance(row.get('manifest'), dict))),
            'reader_captures': readers, 'process_and_failure_captures': process_rows,
            'retention_manifests': retentions, 'copied_fixture_directories': copied,
            'current_paid_capture_count': len(paid), 'current_paid_phases': dict(phases),
            'current_paid_backends': dict(backends), 'current_paid_captures': paid,
            'seed_events': sum(row['seed_queries'] for row in captures),
            'step_events': sum(row['step_queries'] for row in captures),
            'events_are_observations_not_deduplicated_public_opportunities': True,
            'current_original_journals_may_differ_from_pre_reopen_retained_snapshots': True}

    def finish(self):
        self.copy_tree(self.validation, Path('validation'))
        summary, validation_review = self.validation_review()
        captures = self.capture_review(summary)
        source_status = summary.get('status', 'MISSING')
        self.check(source_status in ('PASS', 'FAIL'), 'SOURCE_SUMMARY_STATUS_UNRECOGNIZED', status=source_status)
        terminal_pass = (source_status == 'PASS' and len(validation_review['commands']) == 33
                         and all(row['status'] == 'PASS' for row in validation_review['commands'])
                         and validation_review['recorded_source_gate_complete'])
        if source_status == 'PASS':
            self.check(terminal_pass, 'SUMMARY_PASS_WITH_INCOMPLETE_GATES')
        review = {'schema': 'pon-native-profile-validation-history-review-v1',
            'source_validation_directory': str(self.validation), 'status': source_status,
            'source_summary_status': source_status, 'source_summary': summary,
            'review_status': 'PASS' if terminal_pass and not self.issues else 'FAIL',
            'evidence_integrity_status': 'PASS' if not self.issues else 'INCOMPLETE',
            'validation': validation_review, 'native_captures': captures, 'issues': self.issues,
            'evidence_kind': 'CONTROLLED_FIXTURE', 'qualification_run': False,
            'source_validation_is_not_qualification': True,
            'prior_failed_runs_superseded': False, 'public_query_coverage_established': False,
            'independent_demand_established': False, 'complete_physical_cost_established': False,
            'native_consensus_profile_registered': False, 'chainwork_awarded': 0,
            'production_activation': False,
            'retention_limits': ['Regular files are byte-copied without opening SQLite.',
                'Collector SHA checks are new audit work, not additional historical native queries.',
                'Per-file stability checks do not establish an atomic live-database snapshot.',
                'Create-only output is not tamper-proof immutability or power-loss durability.',
                'Source gate records are checked and retained; their historical execution is not rerun.',
                'Logged controlled customer/payment fixtures do not establish independent external demand.']}
        save_json(self.out / 'review.json', review)
        save(self.out / Path(__file__).name, Path(__file__).read_bytes())
        manifest_rows = []
        for path in sorted(self.out.rglob('*')):
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                raise ValueError('unsafe output tree')
            if path.is_file():
                meta = {'path': path.relative_to(self.out).as_posix(), **file_digest(path)}
                prior = self.files.get(meta['path'])
                if prior is not None and prior != meta:
                    raise ValueError('copied output readback changed: ' + meta['path'])
                manifest_rows.append(meta)
        manifest = {'schema': 'pon-native-profile-validation-history-manifest-v1',
                    'status': source_status, 'review_status': review['review_status'],
                    'source_validation_directory': str(self.validation), 'files': manifest_rows}
        save_json(self.out / 'MANIFEST.json', manifest)
        expected = {row['path']: row for row in manifest_rows}
        expected['MANIFEST.json'] = {'path': 'MANIFEST.json', **file_digest(self.out / 'MANIFEST.json')}
        self.archive.parent.mkdir(parents=True, exist_ok=True)
        with self.archive.open('xb') as output:
            with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
                with tarfile.open(mode='w', fileobj=compressed) as archive:
                    for name, row in sorted(expected.items()):
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode, entry.mtime = row['bytes'], 0o644, 0
                        with (self.out / name).open('rb') as inp:
                            archive.addfile(entry, inp)
            output.flush()
            os.fsync(output.fileno())
        seen = set()
        with tarfile.open(self.archive, 'r:gz') as archive:
            for member in archive:
                name = safe_relative(member.name).as_posix()
                if not member.isfile() or name in seen or name not in expected:
                    raise ValueError('unsafe or duplicate archive member')
                seen.add(name)
                inp = archive.extractfile(member)
                digest, size = hashlib.sha256(), 0
                for chunk in iter(lambda: inp.read(1024 * 1024), b''):
                    digest.update(chunk)
                    size += len(chunk)
                if {'path': name, 'bytes': size, 'sha256': digest.hexdigest()} != expected[name]:
                    raise ValueError('archive byte readback differs: ' + name)
                if file_digest(self.out / name) != {'bytes': size, 'sha256': digest.hexdigest()}:
                    raise ValueError('output byte readback differs: ' + name)
        if seen != set(expected):
            raise ValueError('archive member denominator differs')
        receipt = {'schema': 'pon-native-profile-validation-history-archive-receipt-v1',
            'status': source_status, 'review_status': review['review_status'],
            'evidence_integrity_status': review['evidence_integrity_status'],
            'out': str(self.out), 'archive': str(self.archive), **file_digest(self.archive),
            'member_count': len(expected), 'file_bytes': sum(row['bytes'] for row in expected.values()),
            'readback_verified': True, 'qualification_run': False,
            'collector_sha256': sha(Path(__file__).read_bytes()), 'issues': self.issues}
        print(json.dumps(receipt, sort_keys=True, allow_nan=False), flush=True)
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--validation', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    return Collector(parser.parse_args()).finish()


if __name__ == '__main__':
    raise SystemExit(main())
