"""Reuse this hosted job's sealed Host parent for actual native resource reads.

The controller never provisions the parent or supplies a runtime counter or
Host verdict. A successful standalone sample is not Node/paid-CPU authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

if not __debug__:
    raise RuntimeError('Production resource qualification refuses optimized Python')

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from hia.platform.host_resource import build as resource_build
from hia.platform.host_resource.native_io import FIELDS, MAGIC
from hia.platform.host_resource.rust_oracle import complete_source_manifest
from hia.platform import build as platform_build
from hia.platform.host_checkpoint import build as checkpoint_build
from hia.platform.host_checkpoint import qualify_production as host

ROOT = resource_build.ROOT
MODULE = 'hia/platform/host_resource/qualify_production.py'
TEST = 'hia/platform/host_resource/test_production.py'
EXTRA_INPUTS = (
    MODULE, TEST, 'scripts/ci/run_history_native.py',
    'scripts/ci/check_required_native_test.py', 'scripts/ci/replay_pinned_native.py',
    'config/systemd/trnmponpublic.slice',
)
OPERATIONS = (1, 2, 2)
PARENT = 'sys/fs/cgroup/trnmponpublic.slice'
COUNTERS = ('cpu.stat', 'memory.current', 'pids.current')
CPU_FIELDS = ('cpu_usage_usec', 'cpu_nr_periods', 'cpu_nr_throttled', 'cpu_throttled_usec')
VALUE_FIELDS = (*CPU_FIELDS, 'memory_current_bytes', 'pids_current')
DELTA_FIELDS = ('delta_usage_usec', 'delta_nr_periods', 'delta_nr_throttled', 'delta_throttled_usec')
CPU_KEYS = (b'usage_usec', b'nr_periods', b'nr_throttled', b'throttled_usec')
COUNTER_FLAGS = {'O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'}
TOKEN = r'"(?:[^"\\\r\n]|\\[^\r\n])*"'
LOCK = Path('/run/trnmponpublic-ci-owner.lock')
require = host.require
digest = host.digest
regular = host.regular
write_new = host.write_new


def object_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict, 'JSON_OBJECT_REQUIRED')
    return value


def required_sources():
    require(__debug__, 'Resource source binding refuses optimized Python')
    require(host.ROOT == ROOT and checkpoint_build.ROOT == ROOT,
            'SHARED_HOST_MODULE_FROM_DIFFERENT_CHECKOUT')
    rows = complete_source_manifest()
    for name, value in checkpoint_build.source_manifest().items():
        require(name not in rows or rows[name] == value, 'SOURCE_SET_COLLISION')
        rows[name] = value
    for name in EXTRA_INPUTS:
        raw = regular(ROOT / name)
        value = {'bytes': len(raw), 'sha256': digest(raw)}
        require(name not in rows or rows[name] == value, 'SOURCE_SET_COLLISION')
        rows[name] = value
    require(regular(ROOT / MODULE) == regular(Path(__file__).resolve()),
            'RUNNING_RESOURCE_CONTROLLER_DIFFERS')
    return rows


def require_source_set(report, expected):
    require(type(report.get('source_inputs')) is dict and report['source_inputs'] == expected,
            'PRODUCTION_COMPLETE_SOURCE_SET_REQUIRED')


def validate_build(directory):
    directory = directory.resolve(strict=True)
    raw = regular(directory / 'build.json')
    report = object_json(raw)
    require(report.get('schema') == 'trnm.hia.host-resource-build.v1'
            and report.get('status') == 'PASS', 'RESOURCE_PRODUCTION_BUILD_REQUIRED')
    require_source_set(report, required_sources())
    binding = object_json(regular(ROOT / 'hia/qualification/compiler-binding.json'))
    require(report.get('compiler_sha256') == binding['compiler_sha256']
            and report.get('compiler_qualification_binding') == binding,
            'RESOURCE_PRODUCTION_COMPILER_BINDING_CHANGED')
    image = regular(directory / 'owner.elf')
    require(report.get('executable', {}).get('bytes') == len(image)
            and report['executable'].get('sha256') == digest(image),
            'RESOURCE_PRODUCTION_IMAGE_CHANGED')
    require(report.get('fixture_executable', {}).get('sha256') != digest(image),
            'FIXTURE_CANNOT_REPLACE_RESOURCE_PRODUCTION')
    platform_build.inspect_executable(image)
    return image, report, digest(raw)


def ci_modules():
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    import public_host_ci_observation as observation
    import public_fixture_host_lease as lease
    from verify_ci_source import verify
    for module, relative in ((observation, 'scripts/ci/public_host_ci_observation.py'),
                             (lease, 'scripts/ci/public_fixture_host_lease.py')):
        require(Path(module.__file__).resolve() == ROOT / relative,
                'CI_HELPER_FROM_DIFFERENT_CHECKOUT')
    require(Path(sys.modules[verify.__module__].__file__).resolve()
            == ROOT / 'scripts/ci/verify_ci_source.py', 'SOURCE_VERIFIER_FROM_DIFFERENT_CHECKOUT')
    return observation, lease, verify


def service_name(environment=None, pid=None):
    environment = os.environ if environment is None else environment
    pid = os.getpid() if pid is None else pid
    name = 'trnm-hia-resource-{}-{}-{}-{}.service'.format(
        environment.get('GITHUB_RUN_ID', ''), environment.get('GITHUB_RUN_ATTEMPT', ''),
        environment.get('GITHUB_JOB', ''), pid)
    validate_service(name)
    return name


def validate_service(name):
    require(re.fullmatch(r'trnm-hia-resource-[0-9]+-[0-9]+-[A-Za-z0-9_-]{1,80}-[0-9]+\.service', name),
            'EXPLICIT_OWNED_RESOURCE_SERVICE_REQUIRED')


def service_argv(service, directory, output, lease_root, uid, gid, environment):
    validate_service(service)
    return [
        'sudo', '-n', 'systemd-run', '--unit=' + service, '--wait', '--pipe', '--collect',
        '--service-type=exec', '--expand-environment=no', '--slice=trnmponpublic.slice',
        '--uid=' + str(uid), '--gid=' + str(gid), '--working-directory=' + str(ROOT),
        '--property=KillMode=control-group', '--property=TimeoutStopSec=20s',
        '--property=Delegate=no', '--property=NoNewPrivileges=yes',
        '--property=CapabilityBoundingSet=',
        *['--setenv=' + key + '=' + environment[key]
          for key in host.FORWARDED_ENV if key in environment],
        sys.executable, '-B', str(ROOT / MODULE), '--inside',
        '--build', str(directory), '--lease-receipts', str(lease_root),
        '--output', str(output), '--service', service,
    ]


def lease_directory(path, output, *, inside):
    path = path.absolute()
    output = output.absolute()
    require(path.is_dir() and not path.is_symlink() and path.resolve(strict=True) == path
            and not path.is_relative_to(ROOT), 'CURRENT_CANONICAL_LEASE_ROOT_REQUIRED')
    require(os.environ.get('TRNM_CI_RECEIPT_DIR') == str(path),
            'EXACT_PREVIOUS_RECEIPT_ROOT_REQUIRED')
    require(output.resolve() == output and output.is_relative_to(path)
            and output != path and not output.is_symlink(), 'RESOURCE_CHILD_OUTPUT_REQUIRED')
    if inside:
        require(output.is_dir(), 'CREATED_OWNED_CHILD_OUTPUT_REQUIRED')
    else:
        require(not output.exists(), 'FRESH_RESOURCE_OUTPUT_REQUIRED')
    return path, output


def lock_identity():
    value = LOCK.lstat()
    require(LOCK.resolve(strict=True) == LOCK and stat.S_ISREG(value.st_mode)
            and value.st_uid == 0 and value.st_gid == 0 and stat.S_IMODE(value.st_mode) == 0o444
            and value.st_size == 0, 'EXISTING_JOB_PARENT_LOCK_REQUIRED')
    return {'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid,
            'gid': value.st_gid, 'mode': value.st_mode, 'bytes': value.st_size}


def previous_host(lease_root, source):
    previous = object_json(regular(lease_root / 'report.json'))
    native_raw = regular(lease_root / 'child/native.json')
    native = object_json(native_raw)
    inside = object_json(regular(lease_root / 'child/inside-report.json'))
    expected = {**{'hia/' + k: v for k, v in platform_build.source_manifest().items()},
                **checkpoint_build.source_manifest()}
    require(previous.get('schema') == 'trnm.hia.production-host-controller.v1'
            and previous.get('status') == 'PASS' and not previous.get('cleanup_errors')
            and previous.get('native') == native and inside.get('status') == 'PASS'
            and not inside.get('cleanup_errors'), 'PREVIOUS_REPAIRED_HOST_PRODUCTION_PASS_REQUIRED')
    require(native.get('status') == 'PASS' and native.get('actual_fixed_parent_positive') is True
            and native.get('independent_syscall_trace', {}).get('status') == 'PASS'
            and native.get('source_inputs') == expected, 'PREVIOUS_HOST_SOURCE_TRACE_REQUIRED')
    require(object_json(regular(lease_root / 'source.json')) == source
            == object_json(regular(lease_root / 'source-after.json')),
            'PREVIOUS_HOST_EXACT_SOURCE_CHANGED')
    result = {'report_sha256': digest(regular(lease_root / 'report.json')),
              'native_report_sha256': digest(native_raw), 'creator_service': previous.get('service'),
              'parent_lease': previous.get('parent_lease'),
              'final_parent_lease': previous.get('final_parent_lease'),
              'execution_authority_from_previous_receipt': False}
    stable_prior_binding(result)
    return result


def stable_prior_binding(prior):
    """Reject incomplete previous-phase receipts before any privileged helper."""
    require(type(prior) is dict, 'PRIOR_HOST_RECEIPT_OBJECT_REQUIRED')
    before = prior.get('parent_lease')
    after = prior.get('final_parent_lease')
    keys = {'schema', 'seal_sha256', 'seal_file', 'parent_identity',
            'creator_service', 'current_service', 'host_readiness_only',
            'consensus_or_model_authority'}
    require(type(before) is dict and type(after) is dict and before == after
            and set(before) == keys,
            'PRIOR_HOST_COMPLETE_STABLE_LEASE_REQUIRED')
    require(before['schema'] == 'trnm-ci-public-fixture-parent-binding-v1'
            and before['host_readiness_only'] is True
            and before['consensus_or_model_authority'] is False
            and isinstance(before['creator_service'], str)
            and re.fullmatch(r'trnm-hia-host-[0-9]+-[0-9]+-[A-Za-z0-9_-]{1,80}-[0-9]+\.service',
                             before['creator_service'])
            and prior.get('creator_service') == before['creator_service'] == before['current_service'],
            'PRIOR_HOST_CREATOR_SERVICE_CHANGED')
    return before


def require_prior_lease_binding(prior, current, service):
    """Bind the old successful phase to the freshly validated same-job seal.

    The old service need not remain alive. Only current_service changes; every
    other identity must equal the actual current root-sealed parent binding.
    """
    before = stable_prior_binding(prior)
    require(type(current) is dict and current == {**before, 'current_service': service},
            'PRIOR_HOST_PASS_NOT_BOUND_TO_CURRENT_SEAL')


def c_bytes(token):
    require(re.fullmatch(TOKEN, token) is not None, 'INCOMPLETE_STRACE_STRING')
    result = bytearray()
    text = token[1:-1]
    escapes = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11,
               '\\': 92, '"': 34, "'": 39}
    cursor = 0
    while cursor < len(text):
        value = text[cursor]
        cursor += 1
        if value != '\\':
            require(32 <= ord(value) <= 126, 'UNESCAPED_NONASCII_TRACE_BYTE')
            result.append(ord(value))
            continue
        require(cursor < len(text), 'INCOMPLETE_TRACE_ESCAPE')
        value = text[cursor]
        cursor += 1
        if value in escapes:
            result.append(escapes[value])
        elif value in '01234567':
            digits = value
            while cursor < len(text) and len(digits) < 3 and text[cursor] in '01234567':
                digits += text[cursor]
                cursor += 1
            number = int(digits, 8)
            require(number <= 255, 'NONBYTE_OCTAL_TRACE_ESCAPE')
            result.append(number)
        elif value == 'x':
            digits = text[cursor:cursor + 2]
            require(len(digits) == 2 and re.fullmatch('[0-9a-fA-F]{2}', digits),
                    'INCOMPLETE_HEX_TRACE_ESCAPE')
            result.append(int(digits, 16))
            cursor += 2
        else:
            raise ValueError('UNSUPPORTED_TRACE_ESCAPE')
    return bytes(result)


def parsed_calls(text):
    calls, pids = [], set()
    for index, original in enumerate(text.splitlines()):
        prefix = re.match(r'^\s*(?:\[pid\s+(\d+)\]|(\d+))\s+', original)
        line = original[prefix.end():] if prefix else original
        line = line.strip()
        if prefix:
            pids.add(int(prefix[1] or prefix[2]))
        if not line:
            continue
        if line.startswith('---'):
            require(re.fullmatch(r'--- (?:SIGUSR1|SIGPIPE) \{.*\} ---', line),
                    'UNEXPECTED_NATIVE_TRACE_SIGNAL')
            continue
        if line.startswith('+++'):
            require(line == '+++ exited with 0 +++', 'NATIVE_TRACE_EXIT_FAILED')
            continue
        if re.fullmatch(r'exit\(0\)\s*=\s*\?', line):
            calls.append({'line': index, 'name': 'exit', 'args': '0', 'result': 0, 'tail': ''})
            continue
        match = re.fullmatch(r'([A-Za-z0-9_]+)\((.*)\)\s+=\s+(-?\d+|0x[0-9a-fA-F]+)(?:\s+(.*))?', line)
        require(match is not None, 'UNPARSED_OR_UNFINISHED_NATIVE_TRACE:' + line)
        calls.append({'line': index, 'name': match[1], 'args': match[2],
                      'result': int(match[3], 0), 'tail': match[4] or ''})
    require(calls and calls[-1]['name'] == 'exit'
            and sum(call['name'] == 'exit' for call in calls) == 1,
            'COMPLETE_NATIVE_TRACE_EXIT_REQUIRED')
    return calls, pids


def opening(call):
    require(call['name'] == 'openat', 'COUNTER_OPEN_REQUIRED')
    match = re.fullmatch(r'([^,]+), (' + TOKEN + r'), (.*)', call['args'])
    require(match is not None, 'MALFORMED_NATIVE_OPEN')
    path = c_bytes(match[2]).decode('utf-8')
    flags = match[3].split('|')
    require(len(flags) == len(set(flags)), 'DUPLICATE_NATIVE_OPEN_FLAG')
    return match[1], path, set(flags)


def io_call(call):
    match = re.fullmatch(r'(\d+), (' + TOKEN + r'|0x[0-9a-fA-F]+), (\d+)', call['args'])
    require(match is not None, 'MALFORMED_NATIVE_IO')
    data = None if match[2].startswith('0x') else c_bytes(match[2])
    return int(match[1]), data, int(match[3])


def interrupted(call):
    return call['result'] == -1 and re.match(r'^EINTR(?:\s|$)', call['tail']) is not None


def counter_block(calls, start, active, parent_fd):
    position, bodies, removed = start, {}, []
    require(active.get(parent_fd) == PARENT, 'COUNTER_PARENT_NOT_CURRENTLY_OPEN')
    for name, bound in zip(COUNTERS, (2048, 64, 64), strict=True):
        while True:
            require(position < len(calls), 'INCOMPLETE_COUNTER_OPEN')
            call = calls[position]
            directory, spelling, flags = opening(call)
            require(directory == str(parent_fd) and spelling == name and flags == COUNTER_FLAGS,
                    'COUNTER_RELATIVE_READONLY_PROFILE_CHANGED')
            removed.append(call['line'])
            position += 1
            if interrupted(call):
                continue
            require(call['result'] >= 3 and call['result'] not in active,
                    'COUNTER_OPEN_FAILED_OR_ALIASED')
            counter_fd = call['result']
            break
        require(position < len(calls), 'COUNTER_METADATA_MISSING')
        call = calls[position]
        match = re.fullmatch(r'(\d+), (.*)', call['args'])
        require(call['name'] == 'fstat' and match and int(match[1]) == counter_fd
                and call['result'] == 0 and re.search(r'\bst_mode=S_IFREG(?:[|,}])', match[2]),
                'COUNTER_ACTUAL_REGULAR_FILE_REQUIRED')
        removed.append(call['line'])
        position += 1
        data = bytearray()
        while True:
            require(position < len(calls), 'COUNTER_EOF_MISSING')
            call = calls[position]
            require(call['name'] == 'read', 'COUNTER_COMPLETE_READ_REQUIRED')
            fd, observed, requested = io_call(call)
            require(fd == counter_fd and requested == bound + 1 - len(data),
                    'COUNTER_READ_FD_OR_OVERFLOW_PROBE_CHANGED')
            removed.append(call['line'])
            position += 1
            if interrupted(call):
                continue
            require(call['result'] >= 0 and observed is not None
                    and len(observed) == call['result'] <= requested,
                    'COUNTER_TRACE_BYTES_INCOMPLETE')
            data.extend(observed)
            require(len(data) <= bound, 'COUNTER_BYTE_BOUND_EXCEEDED')
            if call['result'] == 0:
                break
        require(position < len(calls), 'COUNTER_CLOSE_MISSING')
        call = calls[position]
        require(call['name'] == 'close' and call['args'] == str(counter_fd)
                and call['result'] == 0, 'COUNTER_CLOSE_FAILED_OR_WRONG_FD')
        removed.append(call['line'])
        position += 1
        bodies[name] = bytes(data)
    require(position < len(calls) and calls[position]['name'] == 'close'
            and calls[position]['args'] == str(parent_fd) and calls[position]['result'] == 0,
            'SAMPLE_PARENT_NOT_CLOSED_AFTER_COUNTERS')
    require(position + 1 < len(calls) and opening(calls[position + 1])[:2] == ('AT_FDCWD', 'boot'),
            'SECOND_FRESH_CHECK_NOT_IMMEDIATE_AFTER_PARENT_CLOSE')
    return position, bodies, removed


def parsed_values(bodies):
    for name, bound in zip(COUNTERS, (2048, 64, 64), strict=True):
        require(len(bodies[name]) <= bound, 'COUNTER_INPUT_BOUND')
        bodies[name].decode('utf-8')
    def words(raw):
        raw = raw.strip(b' \t\n\r\f')
        return re.split(rb'[ \t\n\r\f]+', raw)
    def integer(raw):
        require(re.fullmatch(rb'\+?[0-9]+', raw) is not None, 'COUNTER_UNSIGNED_INTEGER_REQUIRED')
        value = int(raw)
        require(value <= (1 << 64) - 1, 'COUNTER_UNSIGNED_INTEGER_OVERFLOW')
        return value
    lines = bodies['cpu.stat'].split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    fields = {}
    for line in lines:
        parts = words(line)
        require(len(parts) == 2 and parts[0] not in fields, 'COUNTER_DUPLICATE_OR_MALFORMED_KEY')
        fields[parts[0]] = integer(parts[1])
    require(all(name in fields for name in CPU_KEYS), 'COUNTER_REQUIRED_KEY_MISSING')
    values = [fields[name] for name in CPU_KEYS]
    for name in COUNTERS[1:]:
        parts = words(bodies[name])
        require(len(parts) == 1, 'COUNTER_SCALAR_EXTENT')
        values.append(integer(parts[0]))
    return values


def receipts_from_bytes(raw, *, fixture=False):
    require(len(raw) == 256 * (len(OPERATIONS) + 1), 'FOUR_EXACT_NATIVE_RECEIPTS_REQUIRED')
    rows = [dict(zip(FIELDS, struct.unpack('<32Q', raw[index:index + 256])))
            for index in range(0, len(raw), 256)]
    for sequence, row in enumerate(rows):
        require(row['magic'] == MAGIC and row['fixture'] == int(fixture) and row['error'] == 0
                and row['sequence'] == sequence and row['complete_checks'] == 1 + 2 * sequence
                and row['complete_physical_samples'] == sequence
                and row['complete_counter_reads'] == (3 if sequence else 0)
                and row['operation'] == (OPERATIONS[sequence - 1] if sequence else 0)
                and row['qualified_sample'] == int(sequence > 0)
                and row['private_baseline_present'] == int(sequence > 0)
                and row['resource_gates'] == 0 and row['close_errors'] == 0
                and 0 < row['tid'] < 2**31 and row['tid'] == rows[0]['tid'],
                'NATIVE_RESOURCE_RECEIPT_CONTRACT_CHANGED')
        if sequence:
            require(row['thread_cpu_ns'] > 0 and row['wall_ns'] > 0,
                    'NATIVE_RESOURCE_INTERVAL_MISSING')
        else:
            require(all(row[key] == 0 for key in (*VALUE_FIELDS, *DELTA_FIELDS)),
                    'READY_RECEIPT_CLAIMED_A_SAMPLE')
        if sequence == 1:
            require(all(row[key] == 0 for key in DELTA_FIELDS), 'BASELINE_RECEIPT_CLAIMED_DELTA')
    return rows


def audit_resource_trace(raw, stdout, *, fixture=False):
    """Audit exact bytes and descriptors, then the complete retained Host trace.

    The fixture parameter is only for explicit parser qualification controls.
    Production execution calls this with the default and separately proves its
    actual fixed-parent placement. This pure parser confers no Host authority.
    """
    receipts = receipts_from_bytes(stdout, fixture=fixture)
    text = raw.decode('utf-8')
    normalized = host.normalize_trace(text)
    calls, pids = parsed_calls(normalized)
    tid = receipts[0]['tid']
    require(pids == {tid}, 'TRACE_ACTUAL_NATIVE_TID_DIFFERS')
    active, removed, blocks = {}, set(), []
    emitted, commands, pending = bytearray(), [], bytearray()
    boots = fences = 0
    tids = []
    position = 0
    while position < len(calls):
        call = calls[position]
        name, args, result = call['name'], call['args'], call['result']
        if name == 'getuid':
            require(fixture, 'PRODUCTION_USED_FIXTURE_UID_PATH')
        if name == 'gettid':
            require(result == tid, 'TRACE_GETTID_DIFFERS')
            tids.append(result)
        if name == 'openat':
            directory, spelling, _ = opening(call)
            if spelling in COUNTERS:
                require(spelling == 'cpu.stat' and directory.isdecimal()
                        and position > 0 and calls[position - 1]['name'] == 'newfstatat'
                        and calls[position - 1]['result'] == 0
                        and boots == 3 + 2 * len(blocks) and fences == 2 + 2 * len(blocks)
                        and len(commands) == len(blocks) + 1
                        and len(emitted) == 256 * (len(blocks) + 1) and not pending,
                        'COUNTERS_NOT_AFTER_THIS_REQUEST_FIRST_FRESH_FENCE')
                parent_fd = int(directory)
                next_position, bodies, indexes = counter_block(calls, position, active, parent_fd)
                values = parsed_values(bodies)
                receipt = receipts[len(blocks) + 1]
                require(values == [receipt[key] for key in VALUE_FIELDS],
                        'TRACED_COUNTER_VALUES_DIFFER_FROM_NATIVE_RECEIPT')
                if blocks:
                    old = blocks[-1]['values']
                    delta = []
                    for new, previous in zip(values[:4], old[:4], strict=True):
                        require(new >= previous, 'TRACED_CPU_COUNTER_REWIND')
                        delta.append(new - previous)
                    require(delta == [receipt[key] for key in DELTA_FIELDS],
                            'TRACED_CHECKED_DELTA_DIFFERS_FROM_NATIVE_RECEIPT')
                removed.update(indexes)
                blocks.append({'parent_fd': parent_fd, 'values': values,
                               'counter_bytes_hex': {key: value.hex() for key, value in bodies.items()},
                               'removed_line_indexes': indexes})
                position = next_position
                continue
            if result >= 0:
                require(result not in active, 'TRACE_OPEN_REUSED_LIVE_FD')
                if directory == 'AT_FDCWD':
                    path = spelling
                else:
                    require(directory.isdecimal() and int(directory) in active,
                            'TRACE_RELATIVE_OPEN_WITHOUT_PARENT')
                    path = str(Path(active[int(directory)]) / spelling)
                active[result] = path
            if spelling == 'boot':
                boots += 1
        elif name == 'newfstatat' and boots:
            match = re.fullmatch(r'AT_FDCWD, (' + TOKEN + r'), (.*), ([^,]*)', args)
            require(match is not None, 'TRACE_METADATA_SYNTAX')
            if c_bytes(match[1]).decode() == PARENT and result == 0:
                fences += 1
        elif name == 'close':
            require(args.isdecimal() and int(args) in active and result == 0,
                    'TRACE_CLOSE_FAILED_OR_UNOWNED')
            del active[int(args)]
        elif name == 'read' and args.startswith('0,'):
            fd, data, requested = io_call(call)
            require(requested == 24 - len(pending), 'NATIVE_REQUEST_READ_EXTENT')
            if interrupted(call):
                position += 1
                continue
            require(result >= 0 and data is not None and len(data) == result <= requested,
                    'NATIVE_REQUEST_BYTES_INCOMPLETE')
            if result:
                require(len(commands) < len(OPERATIONS)
                        and len(emitted) == 256 * (len(commands) + 1), 'NATIVE_REQUEST_BEFORE_PRIOR_RECEIPT')
                pending.extend(data)
                if len(pending) == 24:
                    expected = struct.pack('<3Q', OPERATIONS[len(commands)], 0, 4096)
                    require(bytes(pending) == expected, 'NATIVE_REQUEST_OPERATION_OR_CONTROL_CHANGED')
                    commands.append(expected.hex())
                    pending.clear()
            else:
                require(not pending and len(commands) == 3 and len(emitted) == len(stdout),
                        'EARLY_NATIVE_REQUEST_EOF')
                require(position + 1 == len(calls) - 1 and calls[position + 1]['name'] == 'exit',
                        'NATIVE_CALLS_AFTER_FINAL_REQUEST_EOF')
        elif name == 'write':
            fd, data, requested = io_call(call)
            require(fd == 1 and result > 0 and data is not None and len(data) == requested
                    and result <= requested and not active, 'NATIVE_RECEIPT_WRITE_INCOMPLETE_OR_EARLY')
            before = len(emitted)
            emitted.extend(data[:result])
            require(len(emitted) <= len(stdout) and bytes(emitted) == stdout[:len(emitted)],
                    'TRACE_STDOUT_DIFFERS_FROM_NATIVE_RECEIPTS')
            require(before // 256 == (len(emitted) - 1) // 256, 'WRITE_CROSSED_RECEIPT_BOUNDARY')
            if len(emitted) % 256 == 0:
                sequence = len(emitted) // 256 - 1
                require(boots == 2 + 2 * sequence and fences == 1 + 2 * sequence
                        and len(blocks) == sequence and len(commands) == sequence and not pending,
                        'RECEIPT_PRECEDED_COMPLETE_SECOND_FRESH_CHECK')
        position += 1
    require(bytes(emitted) == stdout and len(blocks) == 3 and len(commands) == 3
            and not pending and not active and len(tids) == 4,
            'COMPLETE_RESOURCE_TRACE_COHORT_REQUIRED')
    filtered = '\n'.join(line for index, line in enumerate(normalized.splitlines()) if index not in removed) + '\n'
    observed = host.audit_trace(filtered, expected_checks=7, expected_error=0)
    return {'status': 'PASS', 'raw_trace_sha256': digest(raw), 'filtered_trace_sha256': digest(filtered.encode()),
            'filtered_trace': filtered, 'removed_line_indexes': sorted(removed),
            'counter_blocks': blocks, 'request_frames_hex': commands,
            'stdout_sha256': digest(stdout), 'actual_tid': tid, 'receipts': receipts,
            'shared_host_trace': observed, 'fixture_parser_control': bool(fixture),
            'production_parent_authority_from_parser': False}


def native_production(directory, output, service):
    image, built, build_hash = validate_build(directory)
    tracer = shutil.which('strace')
    require(tracer is not None, 'INDEPENDENT_RESOURCE_PRODUCTION_TRACE_REQUIRED')
    fd = platform_build.sealed_executable(image, 'hia-production-resource-qualified')
    process = None
    drained = False
    primary_failure = None
    stdout, stderr, requests = bytearray(), bytearray(), bytearray()
    rows, contexts = [], []
    started = time.monotonic_ns()
    report = {'schema': 'trnm.hia.production-resource-native.v1', 'status': 'FAIL',
              'executable_sha256': digest(image), 'build_report_sha256': build_hash,
              'source_inputs': built['source_inputs'], 'receipts': rows, 'native_context': contexts,
              'actual_fixed_parent_resource_samples': 0, 'standalone_native_same_tid': False,
              'node_worker_embedding_qualified': False, 'paid_thread_cpu_or_wait4_qualified': False,
              'original_4s_16_service_budget_qualified': False, 'retirement_accepted': False}
    try:
        trace = output / 'syscalls.raw'
        process = subprocess.Popen([tracer, '-f', '-qq', '-s', '4096', '-o', str(trace),
                                    '/proc/self/fd/' + str(fd)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT, env={'PATH': ''}, pass_fds=(fd,), start_new_session=True)
        os.close(fd)
        fd = None
        for sequence in range(4):
            if sequence:
                request = struct.pack('<3Q', OPERATIONS[sequence - 1], 0, 4096)
                requests.extend(request)
                process.stdin.write(request)
                process.stdin.flush()
            raw = host.read_exact(process.stdout, 256, stdout)
            row = dict(zip(FIELDS, struct.unpack('<32Q', raw)))
            rows.append(row)
            require(row['magic'] == MAGIC and row['fixture'] == 0 and row['error'] == 0
                    and row['sequence'] == sequence and row['complete_checks'] == 1 + 2 * sequence
                    and 0 < row['tid'] < 2**31 and row['tid'] == rows[0]['tid'],
                    'PRODUCTION_RESOURCE_NATIVE_RECEIPT_REFUSED')
            proc = Path('/proc') / str(row['tid'])
            membership = (proc / 'task' / str(row['tid']) / 'cgroup').read_text().strip()
            expected = '0::/trnmponpublic.slice/' + service
            require(membership == expected or membership.startswith(expected + '/'),
                    'RESOURCE_NATIVE_THREAD_OUTSIDE_OWNED_SERVICE')
            require(digest((proc / 'exe').read_bytes()) == digest(image),
                    'RUNNING_RESOURCE_PRODUCTION_IMAGE_CHANGED')
            contexts.append({'tid': row['tid'], 'membership': membership,
                             'running_executable_sha256': digest(image)})
        process.stdin.close()
        process.stdin = None
        extra, error = process.communicate(timeout=20)
        stdout.extend(extra)
        stderr.extend(error)
        drained = True
        require(process.returncode == 0 and not extra and not error, 'RESOURCE_NATIVE_COMPLETION_FAILED')
        require(receipts_from_bytes(bytes(stdout)) == rows, 'RESOURCE_RECEIPT_STREAM_CHANGED')
        audited = audit_resource_trace(regular(trace), bytes(stdout))
        filtered = audited.pop('filtered_trace')
        (output / 'syscalls-host-filtered.raw').write_text(filtered)
        write_new(output / 'resource-trace.json', audited)
        report.update(status='PASS', actual_fixed_parent_resource_samples=3,
                      standalone_native_same_tid=True, trace=audited)
    except BaseException as error:
        primary_failure = error
        report['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        errors = []
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as error:
                errors.append('SEALED_RESOURCE_IMAGE_CLOSE:' + repr(error))
        if process is not None and not drained:
            errors.extend(host.drain_owned_process(process, stdout, stderr))
        try:
            final_image, final_build, final_hash = validate_build(directory)
            require(final_image == image and final_hash == build_hash and final_build == built,
                    'RESOURCE_BUILD_CHANGED_DURING_PRODUCTION')
            report['source_after'] = final_build['source_inputs']
        except BaseException as error:
            errors.append('BUILD_AFTER:' + repr(error))
        report['cleanup_errors'] = errors
        if errors:
            report['status'] = 'FAIL'
        report['exit_code'] = None if process is None else process.returncode
        report['elapsed_wall_ns'] = time.monotonic_ns() - started
        report['stdout_sha256'] = digest(stdout)
        report['stderr_sha256'] = digest(stderr)
        (output / 'stdin.raw').write_bytes(requests)
        (output / 'stdout.raw').write_bytes(stdout)
        (output / 'stderr.raw').write_bytes(stderr)
        write_new(output / 'native.json', report)
        if errors and primary_failure is None:
            raise ValueError('OWNED_RESOURCE_PROCESS_CLEANUP_FAILED')
    return report


def inside(directory, lease_root, output, service):
    host.hosted_context()
    validate_service(service)
    require(Path.cwd().resolve() == ROOT, 'ORIGINAL_RESOURCE_CWD_REQUIRED')
    lease_root, output = lease_directory(lease_root, output, inside=True)
    observation, _, verify = ci_modules()
    before = observation.capture('hia-resource-inside-before', service)
    require(not observation.validate(before, inside=True, uid=os.getuid(), gid=os.getgid(), cwd=str(ROOT)),
            'ACTUAL_UNPRIVILEGED_RESOURCE_SERVICE_REQUIRED')
    source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
    require(source == object_json(regular(lease_root / 'source.json')), 'RESOURCE_LEASE_SOURCE_CHANGED')
    write_new(output / 'inside-before.json', before)
    write_new(output / 'inside-source-before.json', source)
    result = {'schema': 'trnm.hia.production-resource-inside.v1', 'status': 'FAIL', 'cleanup_errors': []}
    failure = None
    try:
        native_production(directory, output, service)
        result['status'] = 'PASS'
    except BaseException as error:
        failure = error
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        try:
            after = observation.capture('hia-resource-inside-after', service)
            write_new(output / 'inside-after.json', after)
            require(not observation.validate(after, inside=True, uid=os.getuid(), gid=os.getgid(),
                                             cwd=str(ROOT), reference=before), 'RESOURCE_HOST_CHANGED')
        except BaseException as error:
            result['cleanup_errors'].append('HOST_AFTER:' + repr(error))
        try:
            after = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
            write_new(output / 'inside-source-after.json', after)
            require(source == after, 'RESOURCE_SOURCE_CHANGED_INSIDE')
        except BaseException as error:
            result['cleanup_errors'].append('SOURCE_AFTER:' + repr(error))
        if result['cleanup_errors']:
            result['status'] = 'FAIL'
        write_new(output / 'inside-report.json', result)
        if result['cleanup_errors'] and failure is None:
            raise ValueError('RESOURCE_INSIDE_FINAL_OBSERVATION_FAILED')
    return 0


def outer(directory, lease_root, output):
    host.hosted_context()
    require(Path.cwd().resolve() == ROOT, 'ORIGINAL_RESOURCE_CWD_REQUIRED')
    lease_root, output = lease_directory(lease_root, output, inside=False)
    directory = directory.resolve(strict=True)
    image, built, build_hash = validate_build(directory)
    observation, lease, verify = ci_modules()
    source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
    prior = previous_host(lease_root, source)
    original_lock = lock_identity()
    service = service_name()
    output.mkdir(mode=0o700)
    controller, child = output / 'controller', output / 'child'
    controller.mkdir()
    child.mkdir()
    write_new(output / 'source.json', source)
    result = {'schema': 'trnm.hia.production-resource-controller.v1', 'status': 'FAIL',
              'service': service, 'previous_host': prior, 'cleanup_errors': [],
              'parent_provisioned_by_resource_controller': False, 'local_workstation_provisioned': False,
              'actual_fixed_parent_resource_samples': 0, 'node_worker_embedding_qualified': False,
              'paid_thread_cpu_or_wait4_qualified': False,
              'original_4s_16_service_budget_qualified': False, 'retirement_accepted': False}
    owned = False
    baseline = None
    outer_failure = None
    def command(arguments, name, *, required=True):
        with (controller / (name + '.log')).open('xb') as stream:
            done = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=30)
        require(not required or done.returncode == 0, name + '_FAILED')
        return done.returncode
    try:
        with lease.parent_lock():
            require(lock_identity() == original_lock, 'JOB_PARENT_LOCK_REPLACED')
            primary_failure = None
            try:
                before = observation.capture('hia-resource-before-owned-child', service)
                write_new(controller / 'before-owned-child.json', before)
                command(['systemctl', 'show', observation.UNIT,
                         '--property=' + ','.join(lease.SYSTEMD_PROPERTIES)], 'parent-properties-before')
                parent = lease.validate_for_reuse(before, controller / 'parent-properties-before.log')
                require_prior_lease_binding(prior, parent, service)
                result['parent_lease'] = parent
                baseline = before
                command(['systemctl', 'show', '--property=LoadState', '--value', service],
                        'child-load-state', required=False)
                require((controller / 'child-load-state.log').read_text().strip() == 'not-found',
                        'RESOURCE_CHILD_ALREADY_EXISTS')
                argv = service_argv(service, directory, child, lease_root, os.getuid(), os.getgid(), os.environ)
                result['owned_service_argv'] = argv
                owned = True
                with (controller / 'systemd-run.log').open('xb') as stream:
                    done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                          stderr=subprocess.STDOUT, timeout=180)
                result['systemd_run_exit'] = done.returncode
                require(done.returncode == 0, 'ACTUAL_RESOURCE_SERVICE_FAILED')
                native = object_json(regular(child / 'native.json'))
                inside_report = object_json(regular(child / 'inside-report.json'))
                require(native.get('status') == 'PASS' and native.get('actual_fixed_parent_resource_samples') == 3
                        and native.get('standalone_native_same_tid') is True and not native.get('cleanup_errors')
                        and native.get('executable_sha256') == digest(image)
                        and native.get('build_report_sha256') == build_hash
                        and native.get('source_inputs') == built['source_inputs']
                        and native.get('trace', {}).get('status') == 'PASS'
                        and inside_report.get('status') == 'PASS' and not inside_report.get('cleanup_errors'),
                        'ACTUAL_RESOURCE_NATIVE_EVIDENCE_REQUIRED')
                result.update(status='PASS', native=native, actual_fixed_parent_resource_samples=3)
            except BaseException as error:
                primary_failure = error
                result['failure'] = type(error).__name__ + ': ' + str(error)
                raise
            finally:
                if owned:
                    try:
                        command(['systemctl', 'show', '--property=LoadState', '--value', service],
                                'owned-child-final-state', required=False)
                        if (controller / 'owned-child-final-state.log').read_text().strip() != 'not-found':
                            command(['sudo', '-n', 'systemctl', 'stop', service], 'stop-owned-child')
                    except BaseException as error:
                        result['cleanup_errors'].append('OWNED_RESOURCE_SERVICE_STOP:' + repr(error))
                if baseline is not None:
                    try:
                        after = observation.capture('hia-resource-after-owned-child', service)
                        write_new(controller / 'after-owned-child.json', after)
                        require(not observation.validate(after, inside=False, uid=os.getuid(), gid=os.getgid(),
                                                         cwd=str(ROOT), reference=baseline), 'RESOURCE_PARENT_CHANGED')
                        command(['systemctl', 'show', observation.UNIT,
                                 '--property=' + ','.join(lease.SYSTEMD_PROPERTIES)], 'parent-properties-after')
                        result['final_parent_lease'] = lease.validate_for_reuse(
                            after, controller / 'parent-properties-after.log')
                        require(result['final_parent_lease'] == result['parent_lease']
                                and lock_identity() == original_lock, 'RESOURCE_JOB_LEASE_CHANGED')
                    except BaseException as error:
                        result['cleanup_errors'].append('PARENT_AFTER:' + repr(error))
                if result['cleanup_errors']:
                    result['status'] = 'FAIL'
                    if primary_failure is None:
                        raise ValueError('RESOURCE_PARENT_FINAL_OBSERVATION_FAILED')
    except BaseException as error:
        outer_failure = error
        result['status'] = 'FAIL'
        result['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        try:
            final_source = verify('head', os.environ['TRNM_EXPECTED_SOURCE_SHA'], root=ROOT)
            write_new(output / 'source-after.json', final_source)
            require(source == final_source, 'RESOURCE_SOURCE_CHANGED_OUTSIDE')
        except BaseException as error:
            result['cleanup_errors'].append('SOURCE_AFTER:' + repr(error))
        try:
            final_image, final_build, final_hash = validate_build(directory)
            require(final_image == image and final_build == built and final_hash == build_hash,
                    'RESOURCE_BUILD_CHANGED_OUTSIDE')
            result['source_inputs_after'] = final_build['source_inputs']
        except BaseException as error:
            result['cleanup_errors'].append('BUILD_AFTER:' + repr(error))
        if result['cleanup_errors']:
            result['status'] = 'FAIL'
        try:
            write_new(output / 'report.json', result)
        finally:
            if result['status'] != 'PASS':
                host.emit_failure_evidence(output)
        if result['cleanup_errors'] and outer_failure is None:
            raise ValueError('RESOURCE_SOURCE_OR_BUILD_FINAL_OBSERVATION_FAILED')
    return 0


def main():
    if not __debug__:
        raise RuntimeError('Production resource qualification refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--lease-receipts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--service')
    args = parser.parse_args()
    require(args.inside == bool(args.service), 'EXPLICIT_RESOURCE_SERVICE_MODE_REQUIRED')
    def interrupted_signal(number, _frame):
        raise host.QualificationSignal('Resource qualification interrupted by signal ' + str(number))
    previous = {number: signal.signal(number, interrupted_signal) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        if args.inside:
            return inside(args.build, args.lease_receipts, args.output, args.service)
        return outer(args.build, args.lease_receipts, args.output)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == '__main__':
    raise SystemExit(main())
