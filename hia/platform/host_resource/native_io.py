"""Qualification-only physical driver; native HIA performs every resource read."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import struct
import subprocess
import time

from hia.platform.build import sealed_executable, sha256, write_json
from .cases import DEFAULT_COUNTERS, LIMITS

PARENT = Path('sys/fs/cgroup/trnmponpublic.slice')
MAGIC = int.from_bytes(b'HIAKR001', 'little')
FIELDS = ('magic', 'fixture', 'error', 'sequence', 'complete_checks',
          'complete_physical_samples', 'operation', 'qualified_sample',
          'cpu_usage_usec', 'cpu_nr_periods', 'cpu_nr_throttled', 'cpu_throttled_usec',
          'memory_current_bytes', 'pids_current', 'delta_usage_usec', 'delta_nr_periods',
          'delta_nr_throttled', 'delta_throttled_usec', 'opens', 'reads', 'read_bytes',
          'eintr_retries', 'close_errors', 'tid', 'state_capacity', 'thread_cpu_ns',
          'wall_ns', 'diagnostic_counter_or_rewind_field', 'complete_counter_reads',
          'resource_gates', 'private_baseline_present', 'positive_short_reads')


def require(value, message):
    if not value:
        raise ValueError(message)


def provision(root: Path) -> Path:
    parent = root / PARENT
    parent.mkdir(parents=True, mode=0o700)
    (root / 'controllers').write_bytes(b'cpu memory pids\n')
    (root / 'boot').write_bytes(b'boot-identity\n')
    (root / 'membership').write_bytes(b'0::/trnmponpublic.slice\n')
    for name, raw in {**LIMITS, **DEFAULT_COUNTERS}.items():
        (parent / name).write_bytes(raw)
    return parent


def mutate(root: Path, actions: list[dict]) -> None:
    parent = root / PARENT
    for action in actions:
        kind = action['kind']
        target = action.get('target')
        if target is not None:
            require(target in {*LIMITS, *DEFAULT_COUNTERS, 'boot', 'membership', 'controllers'},
                    'Unknown qualification target')
            path = root / target if target in ('boot', 'membership', 'controllers') else parent / target
        if kind in ('write', 'replace_counter'):
            raw = bytes.fromhex(action['hex'])
            if kind == 'write':
                path.write_bytes(raw)
            else:
                replacement = path.with_name(path.name + '.replacement')
                replacement.write_bytes(raw)
                replacement.replace(path)
        elif kind in ('remove', 'symlink', 'directory', 'fifo', 'socket'):
            if kind == 'symlink':
                saved = path.with_name(path.name + '.saved')
                path.rename(saved)
                path.symlink_to(saved)
            else:
                path.unlink()
                if kind == 'directory':
                    path.mkdir()
                elif kind == 'fifo':
                    os.mkfifo(path, 0o600)
                elif kind == 'socket':
                    # A real socket inode is sufficient for this file-type
                    # refusal. No network endpoint or peer behavior is claimed.
                    os.mknod(path, stat.S_IFSOCK | 0o600)
        elif kind == 'chmod_parent':
            parent.chmod(action['mode'])
        elif kind in ('replace_parent', 'rename_parent', 'symlink_parent'):
            saved = root / 'detached-parent'
            parent.rename(saved)
            if kind == 'replace_parent':
                shutil.copytree(saved, parent)
            elif kind == 'symlink_parent':
                parent.symlink_to(saved, target_is_directory=True)
        else:
            raise ValueError('Unknown resource mutation ' + kind)


class Session:
    def __init__(self, image: bytes, directory: Path, *, fixture=True):
        self.directory = directory
        self.fixture = fixture
        self.image_sha256 = sha256(image)
        self.stdin = bytearray()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.receipts = []
        self.fd_observations = []
        self.started_ns = time.monotonic_ns()
        descriptor = sealed_executable(image, 'hia-resource-qualification')
        try:
            self.process = subprocess.Popen(['/proc/self/fd/' + str(descriptor)],
                cwd=directory, env={'PATH': ''}, pass_fds=(descriptor,),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)
        finally:
            os.close(descriptor)

    def read_exact(self, stream, size, *, timeout=15):
        end = time.monotonic() + timeout
        data = bytearray()
        while len(data) < size:
            remaining = end - time.monotonic()
            require(remaining > 0, 'Native resource observation timed out')
            ready, _, _ = select.select([stream], [], [], remaining)
            require(ready, 'Native resource observation timed out')
            raw = os.read(stream.fileno(), size - len(data))
            require(raw, 'Native resource owner exited before a complete record')
            data.extend(raw)
        (self.stdout if stream is self.process.stdout else self.stderr).extend(data)
        return bytes(data)

    def write(self, data: bytes):
        self.stdin.extend(data)
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def request(self, operation=1, gate=0, chunk=4096):
        self.write(struct.pack('<3Q', operation, gate, chunk))

    def descriptors(self, *, held=False, label='receipt'):
        observed = []
        for descriptor in Path(f'/proc/{self.process.pid}/fd').iterdir():
            try:
                link = os.readlink(descriptor)
                if link.startswith(str(self.directory)):
                    stat = descriptor.stat()
                    observed.append({'fd': int(descriptor.name), 'target': link,
                                     'dev': stat.st_dev, 'ino': stat.st_ino, 'mode': stat.st_mode})
            except FileNotFoundError:
                continue
        if held:
            require(len(observed) == 1 and observed[0]['mode'] & 0o170000 == 0o040000,
                    'Exactly the checked local parent FD must remain during sampling')
        else:
            require(not observed, 'A resource descriptor survived sample completion')
        self.fd_observations.append({'label': label, 'descriptors': observed})
        return observed

    def receipt(self, error=0):
        raw = self.read_exact(self.process.stdout, 256)
        row = dict(zip(FIELDS, struct.unpack('<32Q', raw)))
        self.receipts.append(row)
        require(row['magic'] == MAGIC and row['fixture'] == int(self.fixture),
                'Resource receipt identity mismatch')
        require(row['error'] == error, f'Expected native error {error}, got {row["error"]}')
        if not error:
            require(row['tid'] == self.process.pid, 'Receipt must identify the actual native TID')
            self.descriptors()
        else:
            require(row['qualified_sample'] == 0, 'Failure issued a qualified sample')
        return row

    def gate(self, number):
        require(self.read_exact(self.process.stderr, 8) == struct.pack('<Q', number),
                'Native resource mutation gate mismatch')
        if number >= 5:
            return self.descriptors(held=number != 8, label='gate-' + str(number))
        return []

    def finish(self, error=0):
        self.process.stdin.close()
        self.process.stdin = None
        try:
            out, err = self.process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            out, err = self.process.communicate(timeout=3)
            self.stdout.extend(out)
            self.stderr.extend(err)
            self.save('FAIL', 'native completion timeout')
            raise
        self.stdout.extend(out)
        self.stderr.extend(err)
        require(not out and not err, 'Unexpected extra resource owner output')
        require(self.process.returncode == (64 + error if error else 0), 'Native resource exit mismatch')
        return self.save('PASS')

    def abort(self, reason):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
        try:
            out, err = self.process.communicate(timeout=3)
            self.stdout.extend(out)
            self.stderr.extend(err)
        finally:
            self.save('FAIL', reason)

    def save(self, status, error=None):
        row = {'schema': 'trnm.hia.host-resource-physical-case.v1', 'status': status,
               'error': error, 'pid': self.process.pid, 'exit_code': self.process.returncode,
               'native_image_sha256': self.image_sha256, 'receipts': self.receipts,
               'descriptor_observations': self.fd_observations,
               'stdin_sha256': sha256(self.stdin), 'stdout_sha256': sha256(self.stdout),
               'stderr_sha256': sha256(self.stderr), 'elapsed_wall_ns': time.monotonic_ns()-self.started_ns,
               'fixture_production_authority': False}
        for name, raw in (('stdin.raw', self.stdin), ('stdout.raw', self.stdout), ('stderr.raw', self.stderr)):
            (self.directory / name).write_bytes(raw)
        write_json(self.directory / 'observation.json', row)
        return row


def run_case(image: bytes, directory: Path, case: dict) -> dict:
    directory.mkdir()
    provision(directory)
    session = Session(image, directory)
    comparisons = []
    try:
        initial = session.receipt()
        require(initial['complete_checks'] == 1 and initial['qualified_sample'] == 0,
                'Acquisition must independently check but never fabricate a sample')
        prior = initial
        final_error = 0
        for instruction in case['steps']:
            mutate(directory, instruction['before'])
            session.request(instruction['operation'], instruction['gate'], instruction['chunk'])
            if instruction['gate']:
                before = session.gate(instruction['gate'])
                mutate(directory, instruction['mutation'])
                if instruction['gate'] >= 5:
                    after = session.descriptors(held=instruction['gate'] != 8, label='after-mutation')
                    require([(r['fd'], r['dev'], r['ino']) for r in before]
                            == [(r['fd'], r['dev'], r['ino']) for r in after],
                            'A native counter sample switched its captured parent FD')
                session.write(b'\x01')
            expected = instruction['expected']
            final_error = expected['error']
            actual = session.receipt(final_error)
            values = [actual[name] for name in FIELDS[8:14]]
            delta = [actual[name] for name in FIELDS[14:18]]
            checks = actual['complete_checks'] - prior['complete_checks']
            require(values == expected['values'] and delta == expected['delta'], 'Native sample/delta differs')
            require(checks == expected['checks'], 'Native fresh-check boundary differs')
            require(actual['complete_counter_reads'] == expected['complete_reads'],
                    'Native original read-before-parse order differs')
            if 'rewind_field' in expected:
                require(actual['diagnostic_counter_or_rewind_field'] == 100 + expected['rewind_field'],
                        'CPU checked-sub field order differs')
            if not final_error:
                require(actual['qualified_sample'] == 1 and actual['private_baseline_present'] == 1,
                        'Successful sample missing private qualification/baseline')
                require(actual['thread_cpu_ns'] > 0 and actual['wall_ns'] > 0, 'Native clocks unavailable')
            comparisons.append({'error': final_error, 'values': values, 'delta': delta,
                                'checks': checks, 'complete_reads': actual['complete_counter_reads']})
            prior = actual
            if final_error:
                break
        row = session.finish(final_error)
        row.update({'name': case['name'], 'comparison': comparisons,
                    'case_sha256': sha256(json.dumps(case, sort_keys=True, separators=(',', ':')).encode())})
        write_json(directory / 'observation.json', row)
        return row
    except BaseException as error:
        session.abort(str(error))
        raise
