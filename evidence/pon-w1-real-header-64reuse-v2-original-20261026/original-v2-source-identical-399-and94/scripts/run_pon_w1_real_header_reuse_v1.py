#!/usr/bin/env python3
"""Finite source-only candidate owner for the controlled PNH1/64-reuse component.

Execution requires a separately built exact-commit binary. This script does not
build, dispatch CI, activate production or attest caller-supplied compiler claims.
Every RPC deadline starts in this parent before request writing, never at a
child marker. Native generation, independent replay and sealing share 120s.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import struct
import subprocess
import sys
import time

from run_pon_w1_native_campaign import resource_observation, validate_resources

PROFILE = 'pn1-pnh1-signed-zero-fixed-64-reuse-component-v2'
READER = 'pn1-pnh1-independent-relation-reader-v2'
MIB = 1024 * 1024
TOTAL_SECONDS = 120
CALL_SECONDS = 2
CLEANUP_SECONDS = 5


def require(ok, why):
    if not ok:
        raise ValueError(why)


def uint(value, why, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, why)
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def write_new(path, value):
    data = json_bytes(value)
    require(len(data) <= MIB, 'METADATA_CAP')
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def lower(kind, value):
    soft, hard = resource.getrlimit(kind)
    require((soft == resource.RLIM_INFINITY or soft >= value)
            and (hard == resource.RLIM_INFINITY or hard >= value), 'INHERITED_LIMIT_BELOW_PROFILE')
    resource.setrlimit(kind, (value, value))


def actor_limits():
    # Installed before exec, hence before imports, constructor or Node preparation.
    lower(resource.RLIMIT_AS, 512 * MIB)
    lower(resource.RLIMIT_FSIZE, 8 * MIB)


def birth(pid):
    text = Path(f'/proc/{pid}/stat').read_text()
    return text.rsplit(')', 1)[1].split()[19]


def sha_file(path, cap):
    require(path.is_file() and not path.is_symlink(), 'REGULAR_UNALIASED_INPUT_REQUIRED')
    digest = hashlib.sha256()
    length = 0
    with path.open('rb') as stream:
        while block := stream.read(65536):
            length += len(block)
            require(length <= cap, 'INPUT_CAP')
            digest.update(block)
    return {'bytes': length, 'sha256': digest.hexdigest()}


def source_snapshot(source, deadline):
    def git(*args):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'WHOLE_DEADLINE')
        return subprocess.check_output(['git', '-C', str(source), *args],
                                       timeout=min(CALL_SECONDS, remaining), text=True).strip()
    return {'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain=v1', '--untracked-files=all')}


class Actor:
    """Exactly one persistent process. An error stops this cohort, without restart."""

    def __init__(self, name, command, output, schema, deadline, event_file, owned):
        self.name, self.schema = name, schema
        self.deadline = deadline
        self.event_file = event_file
        self.stdout_bytes = self.stderr_bytes = 0
        self.sequence = 0
        self.pending = bytearray()
        self.eof_observed = {'stdout': False, 'stderr': False}
        self.responses = []
        self.events = []
        self.wait = None
        self.original_birth = None
        self.kill_sent = False
        self.stdout = (output / f'{name}.stdout.jsonl').open('xb')
        self.stderr = (output / f'{name}.stderr.log').open('xb')
        self.selector = selectors.DefaultSelector()
        self.started = time.monotonic()
        self.process = None
        # Register ownership BEFORE spawn/birth/logging can fail. A constructor
        # exception must never strand an unregistered actual child.
        owned.append(self)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, start_new_session=True,
                                        preexec_fn=actor_limits, close_fds=True)
        # These are actual PIDs and actual birth ticks, not a child-supplied ready claim.
        self.original_birth = birth(self.process.pid)
        for stream, kind in ((self.process.stdout, 'stdout'), (self.process.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, kind)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.log({'kind': 'actor_spawned', 'pid': self.process.pid, 'birth': self.original_birth,
                  'command': command, 'actual_session': os.getsid(self.process.pid),
                  'source_binary_attestation': False})

    def log(self, value):
        value.update(actor=self.name, parent_monotonic_ns=time.monotonic_ns())
        raw = json_bytes(value)
        require(self.event_file.tell() + len(raw) <= MIB, 'PARENT_EVENT_CAP')
        self.event_file.write(raw)
        self.event_file.flush()

    def reap_nonblocking(self):
        if self.wait is not None:
            return
        pid, status, usage = os.wait4(self.process.pid, os.WNOHANG)
        if pid:
            self.process.returncode = os.waitstatus_to_exitcode(status)
            self.wait = {'pid': pid, 'birth': self.original_birth, 'raw_wait_status': status,
                         'returncode': self.process.returncode, 'reaped': True,
                         'user_cpu_seconds': usage.ru_utime, 'system_cpu_seconds': usage.ru_stime,
                         'maxrss_bytes': usage.ru_maxrss * 1024,
                         'maxrss_scope': 'this-reaped-process-max-not-simultaneous-whole-tree'}

    def consume(self, timeout):
        rows = []
        for key, _ in self.selector.select(max(0, timeout)):
            try:
                raw = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not raw:
                self.eof_observed[key.data] = True
                self.selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            if key.data == 'stderr':
                self.stderr_bytes += len(raw)
                # Parent file cap stays16MiB; original stderr cap stays4MiB.
                remaining = max(0, 4 * MIB - (self.stderr_bytes - len(raw)))
                self.stderr.write(raw[:remaining])
                self.stderr.flush()
                require(self.stderr_bytes <= 4 * MIB, 'STDERR_CAP_RETAIN_PARTIAL')
                continue
            self.stdout_bytes += len(raw)
            remaining = max(0, 8 * MIB - (self.stdout_bytes - len(raw)))
            self.stdout.write(raw[:remaining])
            self.stdout.flush()
            require(self.stdout_bytes <= 8 * MIB, 'ACTOR_STDOUT_CAP_RETAIN_PARTIAL')
            self.pending.extend(raw)
            require(len(self.pending) <= MIB, 'RPC_FRAME_CAP')
            while b'\n' in self.pending:
                line, _, rest = self.pending.partition(b'\n')
                self.pending = bytearray(rest)
                row = json.loads(line, object_pairs_hook=unique)
                require(row.get('schema') == self.schema, 'RPC_SCHEMA')
                if self.schema == PROFILE:
                    require(uint(row.get('sequence'), 'NATIVE_SEQUENCE_TYPE') == self.sequence, 'NATIVE_SEQUENCE')
                    self.sequence += 1
                require(row.get('kind') in ('response', 'initialized', 'trial_started', 'trial_completed', 'fatal'), 'RPC_KIND')
                if row.get('kind') == 'response':
                    uint(row.get('id'), 'RPC_FRAME_ID_INTEGER', maximum=65)
                    if 'operation_wall_ns' in row:
                        uint(row['operation_wall_ns'], 'RPC_WALL_INTEGER')
                    if 'operation_cpu_ns' in row:
                        uint(row['operation_cpu_ns'], 'RPC_CPU_INTEGER', minimum=1)
                rows.append(row)
        self.reap_nonblocking()
        return rows

    def rpc(self, identifier, operation):
        uint(identifier, 'RPC_REQUEST_ID')
        # Authoritative deadline precedes event writing, stdin writing or any child marker.
        release = time.monotonic()
        end = min(self.deadline, release + CALL_SECONDS)
        require(end > release and self.wait is None, 'RPC_AFTER_TERMINAL_OR_DEADLINE')
        self.log({'kind': 'request_released', 'id': identifier, 'op': operation,
                  'deadline_monotonic_ns': int(end * 1_000_000_000),
                  'timer_origin': 'parent-before-request-write'})
        raw = json_bytes({'id': identifier, 'op': operation})
        offset = 0
        while True:
            remaining = end - time.monotonic()
            require(remaining > 0, 'ORIGINAL_TWO_SECOND_RPC_OR_WHOLE_DEADLINE')
            if offset < len(raw):
                try:
                    offset += os.write(self.process.stdin.fileno(), raw[offset:])
                except BlockingIOError:
                    pass
            for row in self.consume(min(0.01, remaining)):
                require(row['kind'] != 'fatal', 'CHILD_FATAL:' + str(row.get('error')))
                if row['kind'] == 'response':
                    require(offset == len(raw) and uint(row.get('id'), 'RPC_RESPONSE_ID_TYPE') == identifier
                            and row.get('op') == operation, 'RPC_RESPONSE_BINDING')
                    require(time.monotonic() <= end, 'RPC_RETURN_PAST_ORIGINAL_DEADLINE')
                    self.responses.append(row)
                    self.log({'kind': 'response_received', 'id': identifier, 'op': operation,
                              'release_to_response_seconds': time.monotonic() - release})
                    require(time.monotonic() <= end, 'RPC_LOG_OR_FINALIZATION_PAST_ORIGINAL_DEADLINE')
                    return row
            require(self.wait is None, 'CHILD_EXIT_BEFORE_RESPONSE')

    def finish(self):
        end = min(self.deadline, time.monotonic() + CALL_SECONDS)
        self.process.stdin.close()
        while self.wait is None or self.selector.get_map():
            require(time.monotonic() < end, 'TERMINAL_OR_DRAIN_DEADLINE')
            require(not self.consume(min(0.01, end - time.monotonic())), 'EXTRA_TRAILING_EVENT')
        require(not self.pending and all(self.eof_observed.values())
                and self.wait['returncode'] == 0, 'NATIVE_TERMINAL_FAILURE')
        self.close_files()
        require(time.monotonic() <= end, 'TERMINAL_CLOSE_OR_FSYNC_PAST_ORIGINAL_DEADLINE')
        return self.wait

    def abort(self):
        if self.process is None:
            self.close_files()
            return {'launch_failed_before_pid': True, 'registered_process_terminal': None}
        # A real wait4 releases the leader PID/PGID lifetime. NEVER signal that
        # numeric group afterward, even if inherited writers still hold pipes.
        refused_after_reap = self.wait is not None and bool(self.selector.get_map())
        if self.wait is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.kill_sent = True
            except ProcessLookupError:
                pass
        end = time.monotonic() + CLEANUP_SECONDS
        while (self.wait is None or self.selector.get_map()) and time.monotonic() < end:
            try:
                self.consume(min(0.01, end - time.monotonic()))
            except Exception:
                # Keep the original error. Reaping is still attempted; no success is inferred.
                self.reap_nonblocking()
            if self.wait is not None:
                # Drain currently available bytes once more, without waiting for
                # unregistered writers. After reap there is no safe group-signal
                # capability; remaining streams/descendants stay UNKNOWN.
                try:
                    self.consume(0)
                except Exception:
                    pass
                if not all(self.eof_observed.values()):
                    break
        eof_before_close = dict(self.eof_observed)
        pending_before_close = len(self.pending)
        complete_before_close = all(eof_before_close.values()) and not pending_before_close
        self.close_files()
        return {'kill_sent': self.kill_sent, 'actual_wait4': self.wait,
                'registered_process_terminal': self.wait is not None,
                'streams_complete': True if complete_before_close else 'UNKNOWN-no-complete-EOF-before-close',
                'eof_observed_before_close': eof_before_close,
                'pending_bytes_before_close': pending_before_close,
                'group_signal_refused_after_reap': refused_after_reap,
                'unregistered_descendant_terminal': 'UNKNOWN-not-a-whole-tree-census'}

    def close_files(self):
        for stream in (self.stdout, self.stderr):
            if not stream.closed:
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
        if self.process is not None:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        self.selector.close()


def inventory(output, reserve_bytes=0, reserve_files=0):
    uint(reserve_bytes, 'INVENTORY_RESERVE_BYTES', maximum=32 * MIB)
    uint(reserve_files, 'INVENTORY_RESERVE_FILES', maximum=128)
    files, total = [], 0
    for directory, dirs, names in os.walk(output, followlinks=False):
        require(len(dirs) + len(names) <= 128, 'INVENTORY_FANOUT')
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), 'SYMLINK_DIRECTORY')
        for name in names:
            path = Path(directory) / name
            require(path.is_file() and not path.is_symlink(), 'INVENTORY_TYPE')
            size = path.stat().st_size
            require(size <= 16 * MIB, 'ORIGINAL_PARENT_FILE_CAP')
            total += size
            require(total + reserve_bytes <= 32 * MIB
                    and len(files) + 1 + reserve_files <= 128, 'OBSERVED_AGGREGATE_OUTPUT_CAP')
            files.append({'path': str(path.relative_to(output)), 'bytes': size})
    require(total + reserve_bytes <= 32 * MIB and len(files) + reserve_files <= 128,
            'OBSERVED_AGGREGATE_OUTPUT_CAP')
    return {'files': files, 'observed_bytes': total, 'reserved_bytes': reserve_bytes,
            'reserved_files': reserve_files,
            'scope': 'stable-post-reap-size-observation-not-filesystem-hardquota-or-physical-peak'}


def seal_outputs(output, result, started, deadline):
    try:
        return _seal_outputs(output, result, started, deadline)
    except Exception as error:
        failure = ValueError('FINALIZATION_FAILURE:' + type(error).__name__ + ':' + str(error))
        # Final output may already be at its cap. Preserve the original failure
        # in the existing bounded outer stderr channel, without another file or
        # replacing it with the later metadata-cap failure.
        failure.first_error = result.get('first_error')
        raise failure from error


def _close_event_file(stream, first_error):
    errors = []
    try:
        stream.flush()
        os.fsync(stream.fileno())
    except Exception as error:
        errors.append(error)
    finally:
        # A flush/fsync failure must not skip the real close attempt or replace
        # the earlier workload failure on the way to main's existing stderr.
        try:
            stream.close()
        except Exception as error:
            errors.append(error)
    if errors:
        failure = ValueError('EVENT_LOG_FINALIZATION_FAILURE:' + ';'.join(
            type(error).__name__ + ':' + str(error) for error in errors))
        failure.first_error = first_error if first_error is not None else {
            'type': type(errors[0]).__name__, 'message': str(errors[0])}
        raise failure from errors[0]


def _seal_outputs(output, result, started, deadline):
    """Two immutable final records are INCLUDED in the original32MiB/128-file cap.

    Each write_new is <=1MiB. Reserving2MiB/two files neither increases the cap
    nor claims a physical quota. An absent/failed post-write inventory or nonzero
    real outer exit invalidates the provisional records.
    """
    for name in ('owner-result.json', 'post-write-terminal.json'):
        require(not (output / name).exists(), 'FINAL_RECEIPT_NAME_ALREADY_PRESENT')
    before = inventory(output, reserve_bytes=2 * MIB, reserve_files=2)
    result = dict(result)
    result['final_receipt_reservation'] = before
    result['elapsed_seconds_before_final_write'] = time.monotonic() - started
    result['final_write_is_qualification'] = False
    write_new(output / 'owner-result.json', result)
    in_time = time.monotonic() <= deadline
    write_new(output / 'post-write-terminal.json', {
        'schema': PROFILE, 'component_execution_complete': result['component_execution_complete'] and in_time,
        'provisional_requires_actual_exit_zero_and_postwrite_inventory': True,
        'original_120_second_finalization_observed_before_write': in_time,
        'elapsed_seconds': time.monotonic() - started, 'qualifying_execution_receipt': False,
        'whole_work_hardness_qualified': False, 'merge_ready': False})
    # Check the ACTUAL final files, not merely their reservations. Any failure
    # raises and the real owner exits nonzero; provisional JSON is never enough.
    inventory(output)
    return 0 if result['component_execution_complete'] and in_time and time.monotonic() <= deadline else 1


def run(args):
    started = time.monotonic()
    deadline = started + TOTAL_SECONDS
    output = args.output.absolute()
    output.mkdir(parents=False, exist_ok=False)
    actors, terminals = [], []
    result = {'schema': PROFILE, 'recorded_utc': datetime.now(timezone.utc).isoformat(),
              'component_execution_complete': False, 'qualifying_execution_receipt': False,
              'source_binary_attestation': False, 'whole_work_hardness_qualified': False,
              'whole_13_kernel_matrix_qualified': False, 'native_three_fd_qualified': False,
              'hardware_fairness_qualified': False, 'lowest_known_cost_audit_complete': False,
              'full4097_qualified': False, 'merge_ready': False, 'task_complete': False,
              'first_error': None, 'registered_child_terminals': terminals,
              'all_owned_descendants_terminal': 'UNKNOWN-not-a-whole-tree-census',
              'no_build_or_prepared_receipt_is_manufactured': True}
    event_file = None
    try:
        lower(resource.RLIMIT_AS, 3072 * MIB)
        lower(resource.RLIMIT_FSIZE, 16 * MIB)
        before = resource_observation()
        validate_resources(before, 10)
        write_new(output / 'resource-before.json', before)
        source = args.source.resolve(strict=True)
        snapshot = source_snapshot(source, deadline)
        require(snapshot == {'head': args.expected_head, 'tree': args.expected_tree, 'status': ''}, 'EXACT_CLEAN_COMMITTED_SOURCE_REQUIRED')
        result['source_before'] = snapshot
        binary = args.binary.resolve(strict=True)
        binary_meta = sha_file(binary, 192 * MIB)
        with binary.open('rb') as stream:
            elf = stream.read(64)
        require(elf[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', elf, 18)[0] in (62, 183), 'NATIVE_64BIT_ELF_REQUIRED')
        result['binary'] = {'path': str(binary), **binary_meta,
                            'elf_machine': struct.unpack_from('<H', elf, 18)[0],
                            'binding': 'actual-file-hash-not-an-independent-compiler-receipt'}
        result['cpu_identity_observation'] = Path('/proc/cpuinfo').read_text()[:65536]
        # This opt-in component does NOT build a binary or accept a fake prepared ledger.
        # A future qualifying execution still needs exact-commit normal-profile build
        # evidence and independent source admission. All whole-qualification flags stay false.
        event_file = (output / 'parent-events.jsonl').open('xb')
        native = Actor('native', [str(binary), '--profile', PROFILE, '--directory', str(output / 'native-node')],
                       output, PROFILE, deadline, event_file, actors)
        native.rpc(0, 'initialize')
        for index in range(64):
            native.rpc(index + 1, 'search')
        native_seal = native.rpc(65, 'seal')['data']
        require(native_seal['native_component_completed'] is True, 'NATIVE_COMPONENT_INCOMPLETE')
        terminals.append(native.finish())
        reader_path = source / 'scripts/ci/check_pon_w1_real_header_reuse_v1.py'
        reader = Actor('reader', [sys.executable, str(reader_path), '--source', str(source),
                       '--native-log', str(output / 'native.stdout.jsonl'), '--native-pid', str(native.process.pid),
                       '--native-birth', native.original_birth], output, READER, deadline, event_file, actors)
        reader.rpc(0, 'initialize')
        for index in range(64):
            reader.rpc(index + 1, 'search')
        oracle_seal = reader.rpc(65, 'seal')['data']
        require(oracle_seal['independent_relation_component_completed'] is True, 'ORACLE_COMPONENT_INCOMPLETE')
        terminals.append(reader.finish())
        result['native_seal'] = native_seal
        result['independent_relation_seal'] = oracle_seal
        result['source_after'] = source_snapshot(source, deadline)
        require(result['source_after'] == snapshot, 'SOURCE_CHANGED')
        after = resource_observation()
        validate_resources(after, 10)
        write_new(output / 'resource-after.json', after)
        result['inventory'] = inventory(output, reserve_bytes=2 * MIB, reserve_files=2)
        require(time.monotonic() < deadline, 'WHOLE_120_SECONDS_INCLUDING_READER_AND_SEAL')
        result['component_execution_complete'] = True
    except Exception as error:
        result['first_error'] = {'type': type(error).__name__, 'message': str(error)}
        for actor in actors:
            try:
                terminals.append({'actor': actor.name, 'abort': actor.abort()})
            except Exception as cleanup_error:
                # Cleanup diagnostics never replace the original failure or
                # imply that an unobserved process has reached a terminal state.
                terminals.append({'actor': actor.name, 'cleanup_error': str(cleanup_error),
                                  'registered_process_terminal': 'UNKNOWN'})
    finally:
        if event_file is not None:
            _close_event_file(event_file, result['first_error'])
    return seal_outputs(output, result, started, deadline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as error:
        # No extra unbudgeted output file after final-cap failure. Preserve raw
        # records and report a real nonzero outer exit/stream failure instead.
        sys.stderr.write(json.dumps({'schema': PROFILE, 'finalization_failed': str(error),
                                    'first_error': getattr(error, 'first_error', None),
                                    'component_execution_complete': False,
                                    'qualifying_execution_receipt': False, 'merge_ready': False}) + '\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
