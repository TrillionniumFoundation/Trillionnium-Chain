#!/usr/bin/env python3
"""Public PN1 finite native-I/O preparation and one-shot three-FD execution.

This separate component profile never enables V1/V2 full collection. Its
public clean-source preparation creates the source-bound input. It is not a
general sandbox, physical disk quota, full writer or 4097-work qualification.
The local operator, selected toolchain and pinned input receipts are trusted;
internally consistent JSON/hashes are not authentication against that operator.
"""
from __future__ import annotations
import argparse
import errno
from copy import deepcopy
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import stat
import sys
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import bounded_process
from bounded_process import ProcessFailure, run_bounded
from run_pon_identity_churn import (CollectorIO, V2Writer, EVIDENCE_CAPS_V2,
    held_directory, held_file_names, checked_member, identity, json_chunks, now)
from run_pon_w1_native_campaign import (require, sha, source_snapshot,
    validate_source, validate_build_environment, resource_observation, validate_resources)
from read_original_native_campaign import Bundle, strict_json
from check_pon_identity_churn import evidence_ledger_v2, linked_evidence_ledger_v2

MIB = 1024**2
PROFILE = 'pn1-native-io-three-fd-component-v1'
DOMAIN = 'trnm-pon-native-io-three-fd-component-claim-v1'
PREPARED = 'pon-native-io-three-fd-component-prepared-v3'
INVENTORY = 'pon-native-io-three-fd-component-inventory-v1'
EXECUTION = 'pon-native-io-three-fd-component-execution-v1'
CLAIM = 'pon-native-io-three-fd-component-claim-v1'
TERMINAL = 'pon-native-io-three-fd-component-terminal-v1'
DISPATCH = 'pon-native-io-three-fd-component-dispatch-v1'
LINK = 'pon-native-io-three-fd-component-link-v1'
SELECTOR = 'two_process_real_w1_prefix_and_pressure_native_io_component_v1'
TARGET = 'public_v3_identity_campaign'
NATIVE_SCHEMA = 'native-public-v3-identity-churn-native-io-v1'
ACTOR_SCHEMA = 'native-public-v3-identity-churn-supplement-v2'
CAPS = deepcopy(EVIDENCE_CAPS_V2)
PLAN = dict(actors=2, prefix_calls_per_actor=1, pressure_calls_per_actor=2,
    prefix_seconds=30, pressure_seconds=2, readiness_seconds=180, cleanup_seconds=5,
    call_seconds=2, actor_total_call_cap=480, honest_submission_cap=128,
    honest_history_cap=64, rounds=0,
    pressure_schedule='closed-loop-one-in-flight-per-actor', qualification=False)
RELEASE = dict(debug_assertions=False, debuginfo=0, opt_level='3', overflow_checks=False, test=True)
FULL_FLAGS = ('whole_writer_qualified', 'original_three_FD_caller_qualified',
    'independent_reader_qualified', 'full_W1_4097_qualified', 'full_guard_enabled', 'merge_ready')
CLAIM_BYTES = 16 * 1024
BUILD_SECONDS, RUN_SECONDS = 1200, 180
TARGET_BYTES, TARGET_RESERVE = 6 * 1024**3, 512 * MIB


def typed(actual, expected):
    require(type(actual) is type(expected), 'COMPONENT_EXACT_JSON_TYPE_REQUIRED')
    if isinstance(expected, dict):
        require(set(actual) == set(expected), 'COMPONENT_EXACT_FIELDS_REQUIRED')
        for key in expected: typed(actual[key], expected[key])
    elif isinstance(expected, list):
        require(len(actual) == len(expected), 'COMPONENT_EXACT_ARRAY_REQUIRED')
        for value, reference in zip(actual, expected): typed(value, reference)
    else:
        require(actual == expected, 'COMPONENT_FIXED_PROFILE_CHANGED')


def digest(value, length=64):
    require(type(value) is str and len(value) == length
        and all(c in '0123456789abcdef' for c in value), 'CANONICAL_COMPONENT_DIGEST_REQUIRED')
    return value


def component_flags():
    return dict.fromkeys(FULL_FLAGS, False)


def validate_owner_record(row, code):
    require(row['schema'] == 'pon-native-io-component-child-owner-v1'
        and type(row['spawn_count']) is int and row['spawn_count'] == 1
        and type(code) is int and type(row['wait_returncode']) is int
        and row['wait_returncode'] == code and row['reaped'] is True
        and row['original_identity_alive_after_wait'] is False and row['failure'] is None,
        'COMPONENT_NATIVE_CHILD_TERMINAL_UNKNOWN')
    require(all(type(row[key]) is int and row[key] > 0
        for key in ('pid', 'python_pid', 'observed_ppid', 'birth_ticks'))
        and row['pid'] != row['python_pid'] and row['observed_ppid'] == row['python_pid'],
        'COMPONENT_NATIVE_CHILD_BIRTH_OR_PARENT_UNKNOWN')
    return row['pid']


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and os.path.abspath(path) == str(path), 'CANONICAL_ABSOLUTE_COMPONENT_PATH_REQUIRED')
    return path


def environment():
    validate_build_environment(os.environ)
    return {k:v for k,v in os.environ.items() if not k.startswith('TRNM_')}


def resources():
    observed = resource_observation()
    validate_resources(observed, 10)
    return observed


def new_directory(path):
    path = canonical(path)
    parent = held_directory(path.parent)
    child = None
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        return parent, child
    except BaseException:
        if child is not None: os.close(child)
        os.close(parent)
        raise


def owned_directory(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
            'PRIVATE_COMPONENT_DIRECTORY_REQUIRED')
    return identity(info)


def files_at(fd):
    return {name:checked_member(fd, name)[0] for name in held_file_names(fd)}


def origin_at(root, root_fd, parent_fd):
    return dict(root=str(root), leaf=root.name, root_identity=owned_directory(root_fd),
                parent_identity=identity(os.fstat(parent_fd)))


def validate_origin(origin, root, root_fd, parent_fd):
    typed(origin, origin_at(root, root_fd, parent_fd))


class ComponentBundle(Bundle):
    """New schema over the original no-follow held member reader; not V2 input."""
    def __init__(self, root, expected, *, directory_fd, kind):
        self.fd = os.dup(directory_fd)
        try:
            self.root = canonical(root)
            owned_directory(self.fd)
            raw = self._read('artifact-files.json', CAPS['inventory_bytes'])
            require(hashlib.sha256(raw).hexdigest() == digest(expected), 'COMPONENT_INVENTORY_SHA_CHANGED')
            value = strict_json(raw)
            require(value['schema'] == INVENTORY and value['profile'] == PROFILE and value['kind'] == kind,
                    'COMPONENT_INVENTORY_DOMAIN_REQUIRED')
            require(type(value['files']) is list and 0 < len(value['files']) <= 200_000,
                    'COMPONENT_BOUNDED_COMPLETE_INVENTORY_REQUIRED')
            self.files, total = {}, len(raw)
            for row in value['files']:
                name = '/'.join(self.path_parts(row['path']))
                require(name != 'artifact-files.json' and name not in self.files,
                        'COMPONENT_DUPLICATE_OR_RECURSIVE_MEMBER')
                require(type(row['bytes']) is int and 0 <= row['bytes'] <= 256*MIB,
                        'COMPONENT_MEMBER_SIZE_REQUIRED')
                digest(row['sha256'])
                total += row['bytes']
                require(total <= CAPS['artifact_total_bytes'], 'COMPONENT_TOTAL_CAP')
                self.files[name] = row
            self.inventory_sha256, self.manifest_bytes = expected, len(raw)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        require(set(held_file_names(self.fd)) == set(self.files) | {'artifact-files.json'},
                'COMPONENT_UNLISTED_OR_MISSING_MEMBER')
        for name, pin in self.files.items():
            self._read(name, 256*MIB, retain=False, expected=pin)
        require(hashlib.sha256(self._read('artifact-files.json', CAPS['inventory_bytes'])).hexdigest()
                == self.inventory_sha256, 'COMPONENT_INVENTORY_CHANGED')


def native_abi_build(rows, binding):
    """Require emitted normal-C evidence, not merely Cargo/executable success.

    The selected source/toolchain and original fresh-target owner remain trusted.
    This reconstructs a bounded Cargo event; it is not host or native attestation.
    """
    require(type(rows) is list and all(type(row) is dict for row in rows),
            'COMPONENT_CARGO_OBJECT_EVENTS_REQUIRED')
    package = 'path+' + (ROOT/'trillionnium/crates/trnm-sqlite-io-boundary').as_uri() + '#0.1.0'
    selected = [row for row in rows if row.get('reason') == 'build-script-executed'
                and row.get('package_id') == package]
    require(len(selected) == 1, 'COMPONENT_ONE_NATIVE_ABI_BUILD_EVENT_REQUIRED')
    row = selected[0]
    require(set(row) == {'reason', 'package_id', 'linked_libs', 'linked_paths',
                        'cfgs', 'env', 'out_dir'}, 'COMPONENT_NATIVE_ABI_EVENT_FIELDS')
    typed(row['cfgs'], ['trnm_sqlite_layout_witness'])
    require(type(row['env']) is list and len(row['env']) == 2
            and all(type(pair) is list and len(pair) == 2
                    and all(type(item) is str for item in pair) for pair in row['env']),
            'COMPONENT_NATIVE_ABI_ENV_TYPES')
    exported = dict(row['env'])
    typed(exported, {
        'TRNM_SQLITE3_BUILD_FENCE': 'sqlite-3.51.3-normal-native-linux-layout-v3',
        'TRNM_SQLITE3_AMALGAMATION_SHA256':
            '9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5',
    })
    require(type(binding['passed_fd']) is int and 3 <= binding['passed_fd'] <= 2**31-1
            and binding['actual_target'] == '/proc/self/fd/' + str(binding['passed_fd']),
            'COMPONENT_NATIVE_ABI_HELD_TARGET_REQUIRED')
    out = row['out_dir']
    require(type(out) is str and re.fullmatch(re.escape(binding['actual_target'])
            + r'/release/build/trnm-sqlite-io-boundary-[0-9a-f]{16}/out', out) is not None,
            'COMPONENT_NATIVE_ABI_EXACT_TARGET_OUT_DIR')
    typed(row['linked_libs'], ['static=trnm_sqlite_layout_witness'])
    typed(row['linked_paths'], ['native=' + out])
    return dict(schema='pon-native-io-component-native-abi-build-v1',
                cargo_event=deepcopy(row), native_runtime_qualification=False)


def validate_preparation(bundle, head, tree):
    value = bundle.json('prepared.json')
    require(value['schema'] == PREPARED and value['profile'] == PROFILE
        and value['capture_complete'] is True and value['selector_executed'] is False
        and value['failure'] is None and value['head'] == digest(head, 40)
        and value['tree'] == digest(tree, 40) and value['runner_sha256'] == sha(__file__)
        and value['selector'] == SELECTOR and value['build_seconds'] == BUILD_SECONDS
        and value['collector_seconds'] == RUN_SECONDS, 'REAL_COMPONENT_PREPARATION_REQUIRED')
    typed(value['plan'], PLAN)
    typed(value['evidence_caps'], CAPS)
    for key in FULL_FLAGS: require(value[key] is False, 'NO_COMPONENT_FULL_QUALIFICATION')
    require(set(value['files']) | {'prepared.json'} == set(bundle.files), 'COMPONENT_PREPARATION_INCOMPLETE')
    require(all('/' not in name and name not in ('artifact-files.json',) for name in bundle.files),
            'COMPONENT_FLAT_ORIGINAL_PREPARATION_REQUIRED')
    for name, pin in value['files'].items():
        require(pin == {k:bundle.files[name][k] for k in ('bytes', 'sha256')}, 'COMPONENT_PREPARED_MEMBER_CHANGED')
    for label in ('source-before', 'source-after'):
        source = bundle.json(label + '.json')
        row = bundle.json(label + '.step.json')
        raw = bundle.raw(row['stdout'])
        require(source['tested_commit'] == head and source['tested_tree'] == tree
            and source['tracked_worktree_verified'] is True and strict_json(raw) == source,
            'COMPONENT_ACTUAL_CLEAN_SOURCE_CAPTURE_REQUIRED')
        validate_step(bundle, row)
        require(row['command'] == [sys.executable, 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                '--expected-head', head], 'COMPONENT_SOURCE_COMMAND_CHANGED')
    before, after = bundle.json('resource-before.json'), bundle.json('resource-after.json')
    validate_resources(before, 10)
    validate_resources(after, 10)
    require(before['cgroup'] == after['cgroup'], 'COMPONENT_PREPARE_CGROUP_CHANGED')
    build = bundle.json('build.step.json')
    validate_step(bundle, build)
    validate_owner_record(build['native_process_owner'], 0)
    require(build['outer_stage_timeout_seconds'] == BUILD_SECONDS
        and build['command'] == value['build_command'], 'COMPONENT_BUILD_COMMAND_BINDING')
    expected = ['+1.95.0', 'test', '--locked', '--offline', '--release', '--jobs', '2',
        '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', TARGET,
        '--no-run', '--message-format=json']
    require(build['command'][-len(expected):] == expected, 'COMPONENT_ORIGINAL_RELEASE_NO_RUN_REQUIRED')
    prefix = ['taskset', '--cpu-list', ','.join(map(str, before['cpu_affinity'])),
              'prlimit', '--as=3221225472', '--']
    require(build['command'][:6] == prefix and len(build['command']) == 7 + len(expected)
        and canonical(build['command'][6]).is_absolute(), 'COMPONENT_BOUND_BUILD_COMMAND_REQUIRED')
    binding = value['build_target_binding']
    require(type(binding['passed_fd']) is int and 3 <= binding['passed_fd'] <= 2**31-1
        and binding['actual_target'] == '/proc/self/fd/' + str(binding['passed_fd'])
        and type(binding['identity']['device']) is int and type(binding['identity']['inode']) is int
        and binding['identity']['inode'] > 0, 'COMPONENT_TARGET_BINDING_REQUIRED')
    validate_build_monitor(value, binding, build['native_process_owner'])
    artifacts = [strict_json(line) for line in bundle.raw(build['stdout']).splitlines()]
    typed(value['native_abi_build'], native_abi_build(artifacts, binding))
    artifacts = [m for m in artifacts if m.get('reason') == 'compiler-artifact'
        and m.get('target', {}).get('name') == TARGET and m.get('executable')]
    require(len(artifacts) == 1, 'COMPONENT_ONE_ACTUAL_EXECUTABLE_REQUIRED')
    typed(artifacts[0]['profile'], RELEASE)
    binary = value['binary']
    capture = value['build_artifact_capture']
    require(capture['target_identity'] == binding['identity']
        and capture['bytes'] == binary['bytes'] and capture['sha256'] == binary['sha256'],
        'COMPONENT_HELD_ARTIFACT_CAPTURE_BINDING')
    typed(binary['compiler_profile'], RELEASE)
    require(binary['file'] == TARGET + '.bin' and binary['bytes'] == bundle.files[TARGET + '.bin']['bytes']
        and binary['sha256'] == bundle.files[TARGET + '.bin']['sha256']
        and type(binary['bytes']) is int and 0 < 2*binary['bytes'] <= CAPS['frozen_binary_bytes'],
        'COMPONENT_ACTUAL_TWIN_BINARY_CAP')
    return value


def validate_build_monitor(value, binding, owner):
    monitor = value['build_monitor_observation']
    typed(monitor['schema'], 'pon-native-io-component-build-monitor-v1')
    for key, expected in dict(target_cap_bytes=TARGET_BYTES, reserve_bytes=TARGET_RESERVE,
        sample_seconds=5, sample_entries=200_000, watch_interval_seconds=.25,
        first_monitor_error=None, first_monitor_error_type=None, first_monitor_errno=None,
        monitor_error_truncated=False, pending_stop=False, child_active=False,
        kill_attempts=0, kill_delivered=0, watch_thread_alive=False,
        physical_or_instantaneous_quota_claimed=False).items():
        typed(monitor[key], expected)
    typed(monitor['target_identity'], binding['identity'])
    typed(monitor['last_child_pid'], owner['pid'])
    typed(monitor['actual_last_wait'], dict(pid=owner['pid'], returncode=0))
    for key in ('successful_scans', 'scan_retries', 'member_vanish_events',
                'last_scan_entries', 'observed_logical_peak_bytes'):
        require(type(monitor[key]) is int and monitor[key] >= 0, 'COMPONENT_TYPED_BUILD_MONITOR_REQUIRED')
    require(monitor['successful_scans'] > 0
        and monitor['scan_retries'] == monitor['member_vanish_events']
        and monitor['last_scan_entries'] <= 200_000
        and monitor['observed_logical_peak_bytes'] + TARGET_RESERVE <= TARGET_BYTES,
        'COMPONENT_COMPLETE_BOUNDED_BUILD_SCAN_REQUIRED')
    typed(value['build_target_observed_logical_peak_bytes'], monitor['observed_logical_peak_bytes'])
    vanish = monitor['last_member_vanish']
    if monitor['scan_retries'] == 0:
        require(vanish is None, 'COMPONENT_UNEXPLAINED_BUILD_VANISH')
    else:
        require(type(vanish) is dict and set(vanish) == {'errno', 'error', 'truncated'}
            and type(vanish['errno']) is int and vanish['errno'] == errno.ENOENT
            and type(vanish['error']) is str and type(vanish['truncated']) is bool
            and len(json.dumps(vanish['error'], ensure_ascii=True).encode('ascii')) <= 2048,
            'COMPONENT_UNBOUNDED_OR_UNKNOWN_BUILD_VANISH')
    return monitor


def validate_step(bundle, row):
    require(row['returncode'] == 0 and type(row['returncode']) is int
        and row['complete_success'] is True and row['error'] is None,
        'COMPONENT_REAL_STEP_FAILED_OR_UNKNOWN')
    for stream in ('stdout', 'stderr'):
        raw = bundle.raw(row[stream])
        require(row[stream + '_truncated'] is False and len(raw) == row[stream + '_bytes']
            and hashlib.sha256(raw).hexdigest() == row[stream + '_sha256'],
            'COMPONENT_RAW_STREAM_CHANGED_OR_TRUNCATED')


class PreparedComponent:
    def __init__(self, prepared, document_sha256, inventory_sha256, head, tree):
        prepared = canonical(prepared)
        require(prepared.name == 'prepared.json', 'COMPONENT_FIXED_PREPARED_NAME_REQUIRED')
        self.root = prepared.parent
        require(not self.root.is_relative_to(ROOT), 'COMPONENT_PREPARATION_OUTSIDE_SOURCE')
        self.parent_fd = self.binary_fd = self.bundle = None
        directory = None
        try:
            self.parent_fd = held_directory(self.root.parent)
            directory = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            self.bundle = ComponentBundle(self.root, inventory_sha256, directory_fd=directory, kind='prepare')
            require(hashlib.sha256(self.bundle.raw('prepared.json')).hexdigest() == digest(document_sha256),
                    'COMPONENT_EXACT_PREPARED_DOCUMENT_REQUIRED')
            self.value = validate_preparation(self.bundle, head, tree)
            validate_origin(self.value['origin'], self.root, self.bundle.fd, self.parent_fd)
            self.binary_fd = os.open(TARGET + '.bin', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.bundle.fd)
            info = os.fstat(self.binary_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and info.st_mode & 0o222 == 0, 'COMPONENT_READONLY_OWNED_BINARY_REQUIRED')
            self.binding = dict(profile=PROFILE, head=head, tree=tree, prepared_sha256=document_sha256,
                inventory_sha256=inventory_sha256, binary_sha256=self.value['binary']['sha256'],
                binary_bytes=self.value['binary']['bytes'], prepared_root=str(self.root),
                prepared_identity=owned_directory(self.bundle.fd), binary_identity=identity(info))
            self.recheck()
        except BaseException:
            self.close()
            raise
        finally:
            if directory is not None: os.close(directory)

    def pins(self):
        return dict(self.bundle.files, **{'artifact-files.json':dict(bytes=self.bundle.manifest_bytes,
                    sha256=self.binding['inventory_sha256'])})

    def recheck(self):
        validate_origin(self.value['origin'], self.root, self.bundle.fd, self.parent_fd)
        require(identity(os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False))
            == self.binding['prepared_identity'], 'COMPONENT_ORIGINAL_PREPARATION_REPLACED')
        require(identity(os.stat(TARGET + '.bin', dir_fd=self.bundle.fd, follow_symlinks=False))
            == self.binding['binary_identity'], 'COMPONENT_ORIGINAL_BINARY_REPLACED')
        self.bundle.recheck()
        require(hashlib.sha256(self.bundle.raw('prepared.json')).hexdigest() == self.binding['prepared_sha256'],
                'COMPONENT_ORIGINAL_PREPARED_CHANGED')

    def close(self):
        if self.binary_fd is not None: os.close(self.binary_fd); self.binary_fd = None
        if self.bundle is not None: self.bundle.close(); self.bundle = None
        if self.parent_fd is not None: os.close(self.parent_fd); self.parent_fd = None


class NativeChildOwner:
    """Record this bounded owner's actual child, birth and final wait once.

    This dedicated collector is single-threaded during native dispatch; it does
    not support another library spawning through subprocess concurrently.
    """
    def __init__(self):
        self.value = dict(schema='pon-native-io-component-child-owner-v1',
            python_pid=os.getpid(), spawn_count=0, pid=None, birth_ticks=None,
            observed_ppid=None, reaped=False, wait_returncode=None,
            original_identity_alive_after_wait=None, failure=None,
            failed_spawn_streams_closed=None)

    @staticmethod
    def process_identity(pid):
        raw = Path('/proc/' + str(pid) + '/stat').read_text()
        fields = raw.rsplit(')', 1)[1].split()
        return int(fields[19]), int(fields[1])

    def popen(self, *args, **kwargs):
        require(self.value['spawn_count'] == 0, 'COMPONENT_ONE_NATIVE_CHILD_ONLY')
        child = self.original(*args, **kwargs)
        self.value.update(spawn_count=1, pid=child.pid)
        wait = child.wait
        try:
            birth, ppid = self.process_identity(child.pid)
            self.value.update(birth_ticks=birth, observed_ppid=ppid)
            require(birth > 0 and ppid == os.getpid(), 'COMPONENT_ACTUAL_CHILD_BIRTH_REQUIRED')
        except BaseException as error:
            self.value['failure'] = repr(error)
            try:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            finally:
                try:
                    close_errors = []
                    for stream in (child.stdin, child.stdout, child.stderr):
                        if stream is not None:
                            try: stream.close()
                            except OSError as close_error: close_errors.append(str(close_error))
                    self.value['failed_spawn_streams_closed'] = not close_errors and all(
                        stream is None or stream.closed for stream in (child.stdin, child.stdout, child.stderr))
                finally:
                    self.value.update(wait_returncode=wait(), reaped=True)
            raise

        def final_wait(*args, **kwargs):
            code = wait(*args, **kwargs)
            self.value.update(wait_returncode=code, reaped=True)
            try:
                alive = self.process_identity(child.pid)[0] == birth
            except FileNotFoundError:
                alive = False
            self.value['original_identity_alive_after_wait'] = alive
            return code
        child.wait = final_wait
        return child

    def run(self, command, **kwargs):
        self.original = bounded_process.subprocess.Popen
        bounded_process.subprocess.Popen = self.popen
        try:
            return run_bounded(command, b'', **kwargs)
        finally:
            bounded_process.subprocess.Popen = self.original

    def complete(self, code):
        validate_owner_record(self.value, code)


def bounded_context_error(value):
    """Retain an explicit prefix within 2048 ASCII JSON bytes, including quotes."""
    if value is None:
        return None, False
    text, parts, remaining = str(value), [], 2046
    for character in text:
        cost = len(json.dumps(character, ensure_ascii=True)) - 2
        if cost > remaining:
            break
        parts.append(character)
        remaining -= cost
    result = ''.join(parts)
    return result, len(result) != len(text)


def observed_step_exit_code(value):
    """A publication failure preserves evidence, without qualifying an unknown owner."""
    if type(value) is not dict:
        return None
    code = value.get('returncode')
    try:
        validate_owner_record(value.get('native_process_owner'), code)
    except (OSError, ValueError, TypeError, KeyError):
        return None
    return code


class ComponentIO(CollectorIO):
    def __init__(self, output):
        super().__init__(output, 'v2')

    def native_step(self, command, env, dispatch):
        typed(dispatch['schema'], DISPATCH)
        require(dispatch['execution_identity'] == identity(os.fstat(self.writer.fd))
            and dispatch['actual_raw_root'] == env['TRNM_IDENTITY_CAMPAIGN_DIR'], 'COMPONENT_HELD_DISPATCH_REQUIRED')
        return self.owned_step('component', command, env, RUN_SECONDS,
            dict(cwd=dispatch['actual_cwd'], executable_fd=dispatch['executable_fd'],
                 pass_fds=tuple(dispatch['inherited_fds'])), dispatch=dispatch)

    def build_step(self, command, env, target_fd):
        require(env['CARGO_TARGET_DIR'] == '/proc/self/fd/' + str(target_fd),
                'COMPONENT_BUILD_TARGET_FD_REQUIRED')
        return self.owned_step('build', command, env, BUILD_SECONDS,
            dict(cwd=ROOT, pass_fds=(target_fd,)))

    def owned_step(self, name, command, env, timeout, options, *, dispatch=None):
        tokens, opened = [], []
        child_owner = NativeChildOwner()
        stdout = stderr = b''
        start = time.monotonic_ns()
        row = dict(name=name, command=command, cwd=str(ROOT), outer_stage_timeout_seconds=timeout,
            returncode=None, error=None, stdout=name+'.stdout.log', stderr=name+'.stderr.log',
            stdout_truncated=False, stderr_truncated=False)
        if dispatch is not None:
            row['fd_dispatch'] = dispatch
        try:
            for amount in (16*MIB, 4*MIB, 65536): tokens.append(self.writer.reserve('outer', amount))
            for stream_name in (row['stdout'], row['stderr']):
                opened.append(self.writer.open_reserved(stream_name, reject_existing_final=True))
            try:
                result = child_owner.run(command, timeout=timeout, stdout_limit=16*MIB,
                    stderr_limit=4*MIB, env=env, **options)
                row['returncode'], stdout, stderr = result.returncode, result.stdout, result.stderr
            except ProcessFailure as error:
                row.update(returncode=error.returncode, error=str(error), stdout_truncated=error.stdout_truncated,
                           stderr_truncated=error.stderr_truncated)
                stdout, stderr = error.stdout, error.stderr
            except (OSError, ValueError) as error:
                row['error'] = str(error)
            row['native_process_owner'] = child_owner.value
            try:
                child_owner.complete(row['returncode'])
            except (OSError, ValueError) as error:
                row['error'] = row['error'] or str(error)
            for index, (stream_name, raw) in enumerate(((row['stdout'], stdout), (row['stderr'], stderr))):
                self.writer.chunks(stream_name, [raw], tokens[index], exact_bytes=len(raw), opened=opened[index])
            row.update(elapsed_ns=time.monotonic_ns()-start, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
            row['elapsed_seconds'] = row['elapsed_ns']/1_000_000_000
            row['complete_success'] = row['returncode'] == 0 and row['error'] is None
            self.writer.json(name+'.step.json', row, reservation=tokens[2])
            if not row['complete_success']: self.writer.poison(row['error'] or 'COMPONENT_NATIVE_NONZERO')
            return row
        except (OSError, ValueError, TypeError) as error:
            if self.writer.failure_context is None:
                child_error, child_truncated = bounded_context_error(row['error'])
                publication_error, publication_truncated = bounded_context_error(error)
                observed_owner = deepcopy(child_owner.value)
                observed_owner['failure'], owner_truncated = bounded_context_error(observed_owner['failure'])
                # All other owner fields are fixed names and actual bounded
                # kernel PID/birth/wait scalars. Each error uses <=2048 JSON
                # bytes; this context fits the unchanged terminal reservation.
                self.writer.failure_context = dict(
                    schema='pon-native-io-component-owned-step-failure-v1', profile=PROFILE,
                    name=str(name)[:128], returncode=row['returncode'], child_error=child_error,
                    child_error_truncated=child_truncated, publication_error=publication_error,
                    publication_error_truncated=publication_truncated,
                    native_process_owner=observed_owner, native_owner_failure_truncated=owner_truncated,
                    timeout_seconds=str(timeout)[:64], elapsed_ns=time.monotonic_ns()-start,
                    stdout_truncated=row['stdout_truncated'], stderr_truncated=row['stderr_truncated'],
                    observed_stdout_bytes=len(stdout), observed_stderr_bytes=len(stderr),
                    observed_stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                    observed_stderr_sha256=hashlib.sha256(stderr).hexdigest(),
                    raw_preservation_complete=False, **component_flags())
            self.writer.poison(error)
            raise
        finally:
            for directory, _, descriptor in opened:
                if descriptor is not None: os.close(descriptor)
                if directory is not None: os.close(directory)
            for token in tokens: self.writer.cancel(token)


def claim_name(source):
    original = source.value['origin']['root_identity']
    return 'component-execution-claim-v1-' + str(original['device']) + '-' + str(original['inode'])


class ComponentClaim:
    """Only used after public component preparation admission; never a V2 binder."""
    def __init__(self, io, source):
        self.io, self.source = io, source
        self.fd = self.exe = self.cwd = self.parent_fd = None
        self.tokens = []
        self.claim_pin = None
        self.attempted = self.ran = self.finished = False

    def acquire(self):
        io, source = self.io, self.source
        try:
            require(not io.output.is_relative_to(source.root) and not source.root.is_relative_to(io.output),
                    'COMPONENT_DISJOINT_REAL_ROOTS_REQUIRED')
            source.recheck()
            pins = source.pins()
            planned = {'frozen/'+name:pin for name,pin in pins.items()}
            linked_evidence_ledger_v2(planned, 0, pins, {}, CAPS, strict=False)
            imported = evidence_ledger_v2(source.bundle.files, source.bundle.manifest_bytes,
                                          CAPS, strict=False, preparation_only=True)
            io.writer.used.update(outer=imported['bucket_bytes'].get('outer', 0),
                binary=imported['bucket_bytes'].get('binary', 0), inventory=source.bundle.manifest_bytes)
            for _ in range(4): self.tokens.append(io.writer.reserve('outer', CLAIM_BYTES))
            self.parent_fd = held_directory(io.output.parent)
            os.mkdir(claim_name(source), 0o700, dir_fd=source.parent_fd)
            self.fd = os.open(claim_name(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source.parent_fd)
            fd = os.open('owner.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            os.close(fd)
            self.binding = dict(source.binding, execution_root=str(io.output),
                execution_identity=owned_directory(io.writer.fd), claim_identity=owned_directory(self.fd))
            for name,pin in pins.items():
                bucket = 'binary' if name == TARGET+'.bin' else 'inventory' if name == 'artifact-files.json' else 'outer'
                io.writer.copy('frozen/'+name, name, bucket=bucket, expected=pin['sha256'], source_directory_fd=source.bundle.fd)
            directory, leaf = io.writer.parent('frozen/'+TARGET+'.bin')
            try:
                os.chmod(leaf, 0o500, dir_fd=directory, follow_symlinks=False)
                self.exe = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            finally: os.close(directory)
            self.cwd = held_directory(ROOT)
            self.exe_identity = identity(os.fstat(self.exe))
            self.cwd_identity = identity(os.fstat(self.cwd))
            io.bound_cwd_fd = self.cwd
            self.value = dict(schema=CLAIM, domain=DOMAIN, binding=self.binding,
                created_utc=now(), component_only=True, administrator_deletion_resistance=False, **component_flags())
            self.claim_pin = self.external('claim.json', self.value, self.tokens[0])
            io.writer.json('claim-observed.json', self.value, reservation=self.tokens[1])
            self.link = dict(schema=LINK, domain=DOMAIN, binding=self.binding,
                prepared_root=str(source.root), prepared_sha256=source.binding['prepared_sha256'],
                inventory_sha256=source.binding['inventory_sha256'], claim_root=str(source.root.with_name(claim_name(source))),
                claim_pin=self.claim_pin, component_only=True, **component_flags())
            io.json(io.output/'prepared-claim-link.json', self.link)
            self.link_pin = checked_member(io.writer.fd, 'prepared-claim-link.json')[0]
            self.check()
        except BaseException as error:
            io.writer.poison(error)
            raise

    def external(self, name, value, token):
        pieces = list(json_chunks(value))
        raw = b''.join(pieces)
        require(len(raw) <= CLAIM_BYTES, 'COMPONENT_CLAIM_16K_CAP')
        directory = os.dup(self.fd)
        try:
            descriptor = os.open(name+'.partial.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
        except BaseException:
            os.close(directory)
            raise
        self.io.writer.chunks('external-claim/'+name, pieces, token, exact_bytes=len(raw),
            opened=[directory, name, descriptor], terminal=name == 'terminal.json')
        return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def check(self):
        self.source.recheck()
        require(identity(os.stat(self.io.output.name, dir_fd=self.parent_fd, follow_symlinks=False))
            == self.binding['execution_identity'], 'COMPONENT_EXECUTION_ROOT_REPLACED')
        require(identity(os.stat(claim_name(self.source), dir_fd=self.source.parent_fd, follow_symlinks=False))
            == self.binding['claim_identity'], 'COMPONENT_CLAIM_ROOT_REPLACED')
        for name,pin in self.source.pins().items(): checked_member(self.io.writer.fd, 'frozen/'+name, pin)
        require(identity(os.fstat(self.exe)) == self.exe_identity
            and identity(os.stat('frozen/'+TARGET+'.bin', dir_fd=self.io.writer.fd, follow_symlinks=False)) == self.exe_identity,
            'COMPONENT_EXECUTABLE_REPLACED')
        require(identity(os.fstat(self.cwd)) == self.cwd_identity
            and identity(os.stat(ROOT, follow_symlinks=False)) == self.cwd_identity, 'COMPONENT_SOURCE_CWD_REPLACED')
        checked_member(self.fd, 'claim.json', self.claim_pin)
        checked_member(self.io.writer.fd, 'claim-observed.json', self.claim_pin)
        checked_member(self.io.writer.fd, 'prepared-claim-link.json', self.link_pin)

    def run(self, env):
        require(not self.attempted, 'COMPONENT_ONE_SHOT_ONLY')
        self.attempted = True
        self.check()
        root = '/proc/self/fd/'+str(self.io.writer.fd)
        env = dict(env, TRNM_IDENTITY_CAMPAIGN_DIR=root+'/raw', TRNM_IDENTITY_COMPONENT_PROFILE=PROFILE)
        command = [str(self.io.output/'frozen'/(TARGET+'.bin')), '--exact', SELECTOR, '--ignored', '--nocapture', '--test-threads=1']
        dispatch = dict(schema=DISPATCH, domain=DOMAIN, component_only=True,
            executable_fd=self.exe, executable_identity=self.exe_identity,
            executable_sha256=self.source.binding['binary_sha256'], executable_bytes=self.source.binding['binary_bytes'],
            execution_directory_fd=self.io.writer.fd, execution_identity=self.binding['execution_identity'],
            cwd_directory_fd=self.cwd, cwd_identity=self.cwd_identity, actual_command=command,
            actual_executable='/proc/self/fd/'+str(self.exe), actual_cwd='/proc/self/fd/'+str(self.cwd),
            actual_raw_root=env['TRNM_IDENTITY_CAMPAIGN_DIR'], inherited_fds=sorted({self.exe,self.io.writer.fd,self.cwd}),
            **component_flags())
        require(len(dispatch['inherited_fds']) == 3, 'COMPONENT_THREE_DISTINCT_INPUTS_REQUIRED')
        self.ran = True
        return self.io.native_step(command, env, dispatch)

    def finish(self, success, code, failure):
        require(not self.finished, 'COMPONENT_TERMINAL_ALREADY_ATTEMPTED')
        self.finished = True
        if self.fd is None or not hasattr(self, 'binding'):
            self.io.writer.poison(failure or 'COMPONENT_CLAIM_ACQUISITION_INCOMPLETE')
            return
        terminal = dict(schema=TERMINAL, domain=DOMAIN, binding=self.binding,
            claim_sha256=None if self.claim_pin is None else self.claim_pin['sha256'], dispatch_attempted=self.attempted,
            child_owner_called=self.ran, child_exit_observed=code is not None, returncode=code,
            native_owner_success=bool(success), failure=failure, **component_flags())
        errors = []
        for where in ('external', 'observed'):
            try:
                if where == 'external':
                    self.external('terminal.json', terminal, self.tokens[2])
                else:
                    self.io.writer.json('claim-terminal-observed.json', terminal,
                        reservation=self.tokens[3], terminal=True)
            except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
                errors.append(dict(where=where, failure=str(error)))
                self.io.writer.poison(error)
        return errors

    def close(self):
        for token in self.tokens: self.io.writer.cancel(token)
        for name in ('exe', 'cwd', 'fd', 'parent_fd'):
            fd = getattr(self, name)
            if fd is not None:
                if name == 'cwd': self.io.bound_cwd_fd = None
                os.close(fd)
                setattr(self, name, None)


def seal(io, kind, filename, value, success, source=None, claim=None):
    try:
        io.json(io.output/filename, value)
        if not success: io.writer.poison(value.get('failure') or 'COMPONENT_FAILED')
        if io.writer.failure is not None: raise ValueError(io.writer.failure)
        files = files_at(io.writer.fd)
        require('artifact-files.json' not in files, 'COMPONENT_INVENTORY_ALREADY_EXISTS')
        rows = [dict(path=name, **pin) for name,pin in sorted(files.items())]
        manifest = dict(schema=INVENTORY, profile=PROFILE, kind=kind, files=rows)
        size = sum(len(piece) for piece in json_chunks(manifest))
        if source is None:
            evidence_ledger_v2(files, size, CAPS, strict=False, preparation_only=True)
        else:
            source.recheck()
            linked_evidence_ledger_v2(files, size, source.pins(), files_at(claim.fd), CAPS, strict=False)
        io.writer.json('artifact-files.json', manifest, bucket='inventory')
        return True
    except (OSError, ValueError, TypeError, KeyError) as error:
        io.writer.poison(error)
        try: io.writer.terminal(kind, error)
        except (OSError, ValueError, TypeError): pass
        return False


def fail_value(value, stage, error):
    """Preserve the primary failure; secondary observations never turn green."""
    if value.get('failure') is None:
        value['failure'] = str(error)
    value.setdefault('failure_observations', []).append(dict(stage=stage, failure=str(error)))
    if 'capture_complete' in value: value['capture_complete'] = False
    if 'complete_success' in value: value['complete_success'] = False


class BuildStop:
    """Bounded complete target scans; never a physical or instantaneous quota."""
    def __init__(self, target, parent, name, io):
        self.target, self.parent, self.name, self.io = target, parent, name, io
        self.identity = identity(os.fstat(target))
        self.lock, self.stop = threading.Lock(), threading.Event()
        self.child, self.pending, self.error = None, False, None
        self.peak = self.scan_retries = self.vanished_entries = self.scans_completed = 0
        self.last_scan_entries = 0
        self.first_error_type = self.first_error_errno = None
        self.error_truncated = False
        self.last_vanish = None
        self.last_child_pid = self.last_wait = None
        self.kill_attempts = self.kill_delivered = 0
        self.watch_thread = None

    def check_binding(self):
        require(identity(os.fstat(self.target)) == self.identity
            and identity(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity,
            'COMPONENT_BUILD_TARGET_REPLACED')

    def measure(self, *, cancellable=False):
        # The bounds apply to the whole measurement, including every retry.
        entries = 0
        deadline = time.monotonic() + 5
        def scan_error(error):
            raise error
        while True:
            # A missing/replaced top-level name is not an internal Cargo race.
            self.check_binding()
            if cancellable and self.stop.is_set():
                raise InterruptedError('COMPONENT_BUILD_SCAN_STOPPED')
            require(entries <= 200_000 and time.monotonic() < deadline,
                    'COMPONENT_BUILD_SCAN_BOUND_REACHED')
            total = 0
            try:
                for parent, dirs, files, fd in os.fwalk('.', dir_fd=self.target,
                        follow_symlinks=False, onerror=scan_error):
                    for name in dirs+files:
                        if cancellable and self.stop.is_set():
                            raise InterruptedError('COMPONENT_BUILD_SCAN_STOPPED')
                        entries += 1
                        self.last_scan_entries = entries
                        require(entries <= 200_000 and time.monotonic() < deadline,
                                'COMPONENT_BUILD_SCAN_BOUND_REACHED')
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                                'UNKNOWN_BUILD_TARGET_OBJECT')
                        if stat.S_ISREG(info.st_mode):
                            total += info.st_size
                            # Even a later incomplete scan cannot refund what
                            # this measurement already actually observed.
                            self.peak = max(self.peak, total)
                            require(total+TARGET_RESERVE <= TARGET_BYTES,
                                    'COMPONENT_BUILD_TARGET_RESERVE_CAP')
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise
                self.peak = max(self.peak, total)
                self.scan_retries += 1
                self.vanished_entries += 1  # Observed events, not subtree cardinality.
                text, clipped = bounded_context_error(error)
                self.last_vanish = dict(errno=error.errno, error=text, truncated=clipped)
                # Do not skip the entry or accept an incomplete walk. Retry
                # the entire held tree under the original shared bounds.
                continue
            self.check_binding()
            require(time.monotonic() < deadline, 'COMPONENT_BUILD_SCAN_BOUND_REACHED')
            require(total+TARGET_RESERVE <= TARGET_BYTES, 'COMPONENT_BUILD_TARGET_RESERVE_CAP')
            self.last_scan_entries = entries
            self.scans_completed += 1
            self.peak = max(self.peak, total)
            return total

    def monitor_observation(self):
        return dict(schema='pon-native-io-component-build-monitor-v1',
            target_identity=self.identity, target_cap_bytes=TARGET_BYTES,
            reserve_bytes=TARGET_RESERVE, sample_seconds=5, sample_entries=200_000,
            watch_interval_seconds=.25, successful_scans=self.scans_completed,
            scan_retries=self.scan_retries, member_vanish_events=self.vanished_entries,
            last_scan_entries=self.last_scan_entries, last_member_vanish=self.last_vanish,
            observed_logical_peak_bytes=self.peak, first_monitor_error=self.error,
            first_monitor_error_type=self.first_error_type,
            first_monitor_errno=self.first_error_errno, monitor_error_truncated=self.error_truncated,
            pending_stop=self.pending, child_active=self.child is not None,
            last_child_pid=self.last_child_pid, actual_last_wait=self.last_wait,
            kill_attempts=self.kill_attempts, kill_delivered=self.kill_delivered,
            watch_thread_alive=self.watch_thread is not None and self.watch_thread.is_alive(),
            physical_or_instantaneous_quota_claimed=False)

    def request_kill_locked(self):
        if self.child is not None:
            self.kill_attempts += 1
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.kill_delivered += 1
            except ProcessLookupError:
                pass

    def popen(self, *args, **kwargs):
        child = self.original(*args, **kwargs)
        wait = child.wait
        def final_wait():
            while True:
                with self.lock:
                    terminal = os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)
                    if terminal is not None:
                        result = wait()
                        self.last_wait = dict(pid=child.pid, returncode=result)
                        self.child = None
                        return result
                time.sleep(.005)
        child.wait = final_wait
        with self.lock:
            self.child, self.last_child_pid = child, child.pid
            if self.pending:
                self.request_kill_locked()
        return child

    def watch(self):
        while not self.stop.wait(.25):
            try:
                self.measure(cancellable=True)
            except BaseException as error:
                if isinstance(error, InterruptedError) and self.stop.is_set():
                    return
                with self.lock:
                    if self.error is None:
                        self.error, self.error_truncated = bounded_context_error(error)
                        self.first_error_type = type(error).__name__
                        self.first_error_errno = getattr(error, 'errno', None)
                    self.pending = True
                    self.request_kill_locked()
                return

    def retain_failure(self, step, primary, final):
        # The first writer failure remains unchanged. A later NONZERO or seal
        # refusal must not erase the monitor reason or an actual child wait.
        writer = self.io.writer
        if writer.failure_context is None:
            owner = deepcopy(step.get('native_process_owner')) if type(step) is dict else None
            if type(owner) is dict:
                owner['failure'], clipped = bounded_context_error(owner.get('failure'))
            else:
                clipped = False
            child_error, child_clipped = bounded_context_error(step.get('error') if type(step) is dict else None)
            writer.failure_context = dict(
                schema='pon-native-io-component-owned-step-failure-v1', profile=PROFILE,
                name='build', returncode=step.get('returncode') if type(step) is dict else None,
                child_error=child_error, child_error_truncated=child_clipped,
                native_process_owner=owner, native_owner_failure_truncated=clipped,
                raw_preservation_complete=False, **component_flags())
        context = writer.failure_context
        context['schema'] = 'pon-native-io-component-owned-build-step-failure-v2'
        context.setdefault('build_monitor', self.monitor_observation())
        if 'build_boundary_error' not in context:
            text, clipped = bounded_context_error(primary or final)
            context['build_boundary_error'] = text
            context['build_boundary_error_truncated'] = clipped
        if primary is not None and final is not None and primary is not final:
            text, clipped = bounded_context_error(final)
            context.setdefault('build_finalization_error', text)
            context.setdefault('build_finalization_error_truncated', clipped)

    def run(self, command, env):
        self.measure()
        self.original = bounded_process.subprocess.Popen
        self.watch_thread = threading.Thread(target=self.watch, daemon=True)
        bounded_process.subprocess.Popen = self.popen
        step, primary = None, None
        try:
            self.watch_thread.start()
            step = self.io.build_step(command, env, self.target)
            return step
        except BaseException as error:
            primary = error
            raise
        finally:
            bounded_process.subprocess.Popen = self.original
            self.stop.set()
            try:
                self.watch_thread.join(timeout=6)
                require(not self.watch_thread.is_alive(), 'COMPONENT_BUILD_MONITOR_TERMINAL_UNKNOWN')
                self.measure()
                require(self.error is None and self.child is None, self.error or 'BUILD_OWNER_REAP_UNKNOWN')
            except BaseException as final:
                self.retain_failure(step, primary, final)
                if primary is not None:
                    raise primary from final
                raise
            if primary is not None or (type(step) is dict and not step['complete_success']):
                self.retain_failure(step, primary, None)


def capture_built_binary(io, target_fd, declared_target, advertised):
    """Read only the original held target; no ambient artifact path is opened."""
    path = canonical(advertised)
    roots = (Path('/proc/self/fd/'+str(target_fd)), declared_target)
    relative = next((path.relative_to(root) for root in roots if path.is_relative_to(root)), None)
    require(relative is not None, 'COMPONENT_BUILD_ARTIFACT_OUTSIDE_TARGET')
    parts = Bundle.path_parts(relative.as_posix())
    require(parts[0] == 'release' and len(parts) >= 2, 'COMPONENT_RELEASE_ARTIFACT_PATH')
    parent = os.dup(target_fd)
    descriptor = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
            and 0 < 2*before.st_size <= CAPS['frozen_binary_bytes'], 'COMPONENT_OWNED_TWIN_BINARY_CAP')
        require(os.read(descriptor, 4) == b'\x7fELF', 'COMPONENT_REAL_ELF_REQUIRED')
        os.lseek(descriptor, 0, os.SEEK_SET)
        fingerprint = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        digest = hashlib.sha256()
        def pieces():
            while block := os.read(descriptor, 65536):
                digest.update(block)
                yield block
            require(fingerprint(os.fstat(descriptor)) == fingerprint(before)
                and fingerprint(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) == fingerprint(before),
                'COMPONENT_HELD_BUILD_ARTIFACT_CHANGED')
        reservation = io.writer.reserve('binary', before.st_size)
        io.writer.chunks(TARGET+'.bin', pieces(), reservation, exact_bytes=before.st_size)
        pin = dict(bytes=before.st_size, sha256=digest.hexdigest())
        checked_member(io.writer.fd, TARGET+'.bin', pin)
        return pin, dict(target_identity=identity(os.fstat(target_fd)), relative_path=relative.as_posix(),
            source_identity=identity(before), bytes=before.st_size, sha256=pin['sha256'])
    finally:
        if descriptor is not None: os.close(descriptor)
        os.close(parent)


def prepare(args, io):
    env = environment()
    target = canonical(args.target_dir)
    require(not target.is_relative_to(ROOT) and not target.is_relative_to(io.output)
        and not io.output.is_relative_to(target), 'COMPONENT_ISOLATED_FRESH_TARGET_REQUIRED')
    value = dict(schema=PREPARED, profile=PROFILE, head=args.expected_head, tree=args.expected_tree,
        created_utc=now(), capture_complete=False, selector_executed=False, failure=None,
        plan=PLAN, evidence_caps=CAPS, selector=SELECTOR, build_seconds=BUILD_SECONDS,
        collector_seconds=RUN_SECONDS, runner_sha256=sha(__file__), **component_flags())
    target_parent = target_fd = None
    try:
        parent = held_directory(io.output.parent)
        try:
            value['origin'] = origin_at(io.output, io.writer.fd, parent)
        finally:
            os.close(parent)
        io.json(io.output/'resource-before.json', resources())
        io.source('source-before', env, args.expected_head, args.expected_tree)
        target_parent, target_fd = new_directory(target)
        env.update(CARGO_TARGET_DIR='/proc/self/fd/'+str(target_fd), CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
                   RUSTUP_TOOLCHAIN='1.95.0', PYTHONDONTWRITEBYTECODE='1')
        command = ['taskset', '--cpu-list', ','.join(map(str, sorted(os.sched_getaffinity(0)))),
            'prlimit', '--as=3221225472', '--', str(canonical(args.cargo)), '+1.95.0', 'test',
            '--locked', '--offline', '--release', '--jobs', '2', '--manifest-path', 'trillionnium/Cargo.toml',
            '-p', 'trnm-pon-node', '--test', TARGET, '--no-run', '--message-format=json']
        value['build_command'] = command
        value['build_target_binding'] = dict(identity=identity(os.fstat(target_fd)),
            passed_fd=target_fd, actual_target=env['CARGO_TARGET_DIR'], declared_path=str(target))
        build_owner = BuildStop(target_fd, target_parent, target.name, io)
        build = build_owner.run(command, env)
        value['build_target_observed_logical_peak_bytes'] = build_owner.peak
        value['build_monitor_is_not_instantaneous_or_physical_peak_proof'] = True
        value['physical_build_quota_claimed'] = False
        require(build['complete_success'], 'COMPONENT_RELEASE_BUILD_FAILED')
        rows = [strict_json(line) for line in checked_member(io.writer.fd, build['stdout'], retain=True, limit=16*MIB)[1].splitlines()]
        value['native_abi_build'] = native_abi_build(rows, value['build_target_binding'])
        artifacts = [r for r in rows if r.get('reason') == 'compiler-artifact'
            and r.get('target', {}).get('name') == TARGET and r.get('executable')]
        require(len(artifacts) == 1, 'COMPONENT_ONE_RELEASE_EXECUTABLE_REQUIRED')
        typed(artifacts[0]['profile'], RELEASE)
        build_owner.measure()
        binary, capture = capture_built_binary(io, target_fd, target, artifacts[0]['executable'])
        build_owner.measure()
        value['build_artifact_capture'] = capture
        os.chmod(TARGET+'.bin', 0o500, dir_fd=io.writer.fd, follow_symlinks=False)
        value['binary'] = dict(binary, file=TARGET+'.bin', compiler_profile=artifacts[0]['profile'])
        io.source('source-after', env, args.expected_head, args.expected_tree)
        after = resources()
        io.json(io.output/'resource-after.json', after)
        require(after['cgroup'] == strict_json(checked_member(io.writer.fd, 'resource-before.json', retain=True)[1])['cgroup'],
                'COMPONENT_PREPARE_RESOURCE_SCOPE_CHANGED')
        value['build_target_observed_logical_peak_bytes'] = build_owner.peak
        value['build_monitor_observation'] = build_owner.monitor_observation()
        value['capture_complete'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail_value(value, 'prepare', error)
    finally:
        if target_fd is not None: os.close(target_fd)
        if target_parent is not None: os.close(target_parent)
    value['completed_utc'] = now()
    try:
        value['files'] = files_at(io.writer.fd)
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail_value(value, 'final-prepare-files', error)
    return seal(io, 'prepare', 'prepared.json', value, value['capture_complete'])


def execute(args, io):
    env = environment()
    value = dict(schema=EXECUTION, profile=PROFILE, head=args.expected_head, tree=args.expected_tree,
        started_utc=now(), complete_success=False, selector_executed=False, failure=None,
        plan=PLAN, evidence_caps=CAPS, selector=SELECTOR, prepared_sha256=args.prepared_sha256,
        inventory_sha256=args.prepared_inventory_sha256, runner_sha256=sha(__file__),
        component_reader_required=True, component_readback_complete=False, **component_flags())
    source = claim = None
    try:
        source = PreparedComponent(args.prepared, args.prepared_sha256, args.prepared_inventory_sha256,
                                   args.expected_head, args.expected_tree)
        claim = ComponentClaim(io, source)
        claim.acquire()
        before = resources()
        io.json(io.output/'resource-before.json', before)
        io.source('source-before', env, args.expected_head, args.expected_tree)
        env.update(TRNM_IDENTITY_SOURCE_HEAD=args.expected_head, TRNM_IDENTITY_SOURCE_TREE=args.expected_tree)
        value['selector_executed'] = True
        value['step'] = claim.run(env)
        require(value['step']['complete_success'], 'COMPONENT_NATIVE_OWNER_FAILED')
        value['complete_success'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail_value(value, 'execute', error)
    finally:
        value['post_observations'] = {}
        if value['selector_executed']:
            for label in ('inputs', 'source', 'resources'):
                try:
                    if label == 'inputs': claim.check()
                    elif label == 'source': io.source('source-after', env, args.expected_head, args.expected_tree)
                    else:
                        after = resources()
                        io.json(io.output/'resource-after.json', after)
                        require(after['cgroup'] == before['cgroup'], 'COMPONENT_EXECUTE_CGROUP_CHANGED')
                    value['post_observations'][label] = dict(success=True, failure=None)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    fail_value(value, 'post-' + label, error)
                    value['post_observations'][label] = dict(success=False, failure=str(error))
        try:
            if claim is not None:
                try:
                    observed_step = value.get('step')
                    if observed_step is None:
                        context = io.writer.failure_context
                        if (type(context) is dict
                            and context.get('schema') == 'pon-native-io-component-owned-step-failure-v1'
                            and context.get('profile') == PROFILE and context.get('name') == 'component'):
                            observed_step = context
                            value['failed_step_observation'] = deepcopy(context)
                    terminal_errors = claim.finish(value['complete_success'],
                        observed_step_exit_code(observed_step), value['failure'])
                    for failure in terminal_errors or []:
                        fail_value(value, 'claim-terminal-' + failure['where'], failure['failure'])
                except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
                    fail_value(value, 'claim-terminal', error)
            value['completed_utc'] = now()
            return seal(io, 'execute', 'results.json', value, value['complete_success'], source, claim)
        finally:
            if claim is not None: claim.close()
            if source is not None: source.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'execute'))
    parser.add_argument('--profile', choices=(PROFILE,), required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--cargo', type=Path)
    parser.add_argument('--prepared', type=Path)
    parser.add_argument('--prepared-sha256')
    parser.add_argument('--prepared-inventory-sha256')
    args = parser.parse_args()
    digest(args.expected_head, 40); digest(args.expected_tree, 40)
    validate_source(source_snapshot(), args.expected_head, args.expected_tree)
    environment()
    resources()
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:4])
    output = canonical(args.out)
    require(not output.is_relative_to(ROOT), 'COMPONENT_OUTPUT_OUTSIDE_SOURCE_REQUIRED')
    require((args.target_dir and args.cargo) if args.mode == 'prepare'
        else (args.prepared and args.prepared_sha256 and args.prepared_inventory_sha256), 'COMPONENT_MODE_ARGUMENTS_REQUIRED')
    parent, created = new_directory(output)
    io = None
    try:
        io = ComponentIO(output)
        require(owned_directory(io.writer.fd) == owned_directory(created), 'COMPONENT_NEW_OUTPUT_REPLACED')
        passed = prepare(args, io) if args.mode == 'prepare' else execute(args, io)
        print(json.dumps(dict(out=str(output), mode=args.mode, component_process_success=passed,
            component_readback_complete=False, **component_flags())))
        return 0 if passed else 1
    finally:
        if io is not None: io.writer.close()
        os.close(created)
        os.close(parent)


if __name__ == '__main__':
    raise SystemExit(main())
