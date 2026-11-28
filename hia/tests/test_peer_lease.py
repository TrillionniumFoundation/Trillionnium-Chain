"""Private native peer-lease values against the complete executed Rust crate.

Retained original OS tests remain mandatory. An unavailable Unix socket fails
that original gate; the captured value comparisons do not replace it.
"""
from __future__ import annotations
import hashlib
import copy
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from .peer_lease_native import PeerLeaseNative, FAULT_SOURCE, SOURCE

ROOT = Path(__file__).resolve().parents[2]
MAX = (1 << 64) - 1
BODY_MAX = 8 * 1024 * 1024
PROJECTION_DOMAIN = b'trnm.portable-g1.payload-recovery-status-projection.v1'


def words(*values):
    return struct.pack('<' + 'Q' * len(values), *values)


def digest(byte):
    return bytes([byte]) * 32


def operation(op, payload=b''):
    return words(op, len(payload)) + payload


def session(commands):
    return b'PLV10001' + words(len(commands)) + b''.join(commands)


def scope(local=None, remote=None, peer=None, direction=1, epoch=7):
    return (digest(1) if local is None else local) + (digest(2) if remote is None else remote) + (digest(3) if peer is None else peer) + words(direction, epoch)


def namespace(local=None, peer=None, run=None, network=None, epoch=7):
    return b''.join(digest(i) if value is None else value for i, value in
                    [(1, local), (3, peer), (4, run), (5, network)]) + words(epoch)


def token(handle=1, session_id=None, generation=8, expiry=0, record_hash=None):
    return words(handle) + (digest(7) if session_id is None else session_id) + words(generation, expiry) + (digest(8) if record_hash is None else record_hash)


def frame(handle=1, run=None, network=None, session_id=None, generation=8, sequence=0, kind=1, length=0, fingerprint=None):
    return words(handle) + b''.join(digest(i) if value is None else value for i, value in
        [(4, run), (5, network), (7, session_id)]) + words(generation, sequence, kind, length) + (digest(8) if fingerprint is None else fingerprint)


def target(index=1, record_hash=None, remote=None, direction=1, session_id=None, generation=8, sequence=0, kind=1, length=0, fingerprint=None):
    return words(index) + (digest(6) if record_hash is None else record_hash) + (digest(2) if remote is None else remote) + words(direction) + (digest(7) if session_id is None else session_id) + words(generation, sequence, kind, length) + (digest(8) if fingerprint is None else fingerprint)


def status(kind, *, count=0, head_count=0, temporary=0, head=None, revision=0, ack=None, acknowledgement=None):
    if kind == 1:
        return words(kind, count, head_count, temporary)
    if kind == 2:
        return words(kind, count, temporary)
    if kind == 3:
        return words(kind, count) + (digest(0) if head is None else head)
    return words(kind, count) + (digest(0) if head is None else head) + words(revision) + (digest(0) if ack is None else ack) + (digest(0) if acknowledgement is None else acknowledgement)


def projection(kind=4, *, namespace_digest=None, target_bytes=None, status_bytes=None):
    # Test vectors only: the actual original decoder independently verifies
    # every field and digest before producing any comparison answer.
    t = target() if target_bytes is None else target_bytes
    s = status(kind) if status_bytes is None else status_bytes
    read = lambda data, at: struct.unpack_from('<Q', data, at)[0]
    p = b'TRNPRSP1' + bytes([1, 0, 0, 0]) + (digest(0) if namespace_digest is None else namespace_digest)
    p += struct.pack('>Q', read(t, 0)) + t[8:72] + bytes([read(t, 72)]) + t[80:112]
    p += struct.pack('>QQBI', read(t, 112), read(t, 120), read(t, 128), read(t, 136)) + t[144:176]
    p += bytes([kind]) + struct.pack('>Q', read(s, 8))
    if kind == 1:
        p += struct.pack('>QI', read(s, 16), read(s, 24))
    elif kind == 2:
        p += struct.pack('>I', read(s, 16))
    else:
        p += s[16:48]
        if kind == 4:
            p += struct.pack('>Q', read(s, 48)) + s[56:120]
    return seal_projection(p + bytes([1, 0, 0]))


def seal_projection(prefix):
    return prefix + hashlib.sha256(PROJECTION_DOMAIN + struct.pack('>Q', len(prefix)) + prefix).digest()


def decode_reply(raw):
    if len(raw) < 32 or raw[:8] != b'PLR10001':
        raise AssertionError('Missing complete peer-lease result header')
    count, total, reserved = struct.unpack_from('<3Q', raw, 8)
    if total != len(raw) or reserved:
        raise AssertionError('Non-exact peer-lease result extent')
    rows = []; at = 32
    for _ in range(count):
        op, status_code, length = struct.unpack_from('<3Q', raw, at); at += 24
        data = raw[at:at + length]; at += length
        if len(data) != length:
            raise AssertionError('Truncated peer-lease result')
        rows.append((op, status_code, data))
    if at != len(raw):
        raise AssertionError('Trailing peer-lease result bytes')
    return rows


def actual_test_outcome(case, result):
    problems = []
    for name in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
        for item in getattr(result, name, []):
            candidate = item[0] if isinstance(item, tuple) else item
            if candidate is case or getattr(candidate, 'test_case', None) is case:
                problems.append(name)
    return {'test': case.id(), 'status': 'FAIL' if problems else 'PASS', 'problems': problems}


def validate_retained_observation(execution, before, after, current, stdout, stderr):
    if not current or before != after or before != current:
        raise ValueError('Retained original execution is not bound to the exact unchanged source')
    argv = execution.get('argv', [])
    if len(argv) != 15 or not Path(argv[0]).is_absolute() or Path(argv[0]).name != 'cargo':
        raise ValueError('Retained original command has a different domain')
    expected = [argv[0], 'test', '--offline', '--locked', '--no-fail-fast', '--manifest-path', argv[6],
                '-p', 'trnm-peer-lease', '--all-features', '--target-dir', argv[11],
                '--message-format=json', '--', '--test-threads=1']
    # Keep the exact argv length separate from this list so accidental extra
    # cargo target flags or libtest filters cannot be silently admitted.
    if argv != expected or not Path(argv[6]).is_absolute() or not Path(argv[11]).is_absolute():
        raise ValueError('Retained original execution filtered or changed the test domain')
    if (execution.get('source_unchanged') is not True
            or execution.get('retained_original_tests_not_filtered') is not True
            or execution.get('timed_out') is not False
            or type(execution.get('returncode')) is not int):
        raise ValueError('Retained original execution is incomplete')
    for name, raw in [('stdout', stdout), ('stderr', stderr)]:
        wanted = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        if execution.get(name) != wanted:
            raise ValueError('Retained original raw stream differs: ' + name)


class PeerLeaseValues(unittest.TestCase):
    @classmethod
    def identities(cls, paths):
        return {str(p.relative_to(ROOT)): cls.identity(p.read_bytes()) for p in paths}

    @staticmethod
    def identity(raw):
        return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    @classmethod
    def setUpClass(cls):
        destination = os.environ.get('HIA_PEER_LEASE_OUTPUT')
        cls.temporary = None if destination else tempfile.TemporaryDirectory(prefix='trnm-peer-values-')
        cls.output = Path(destination).absolute() if destination else Path(cls.temporary.name)
        if destination:
            cls.output.mkdir(parents=True, exist_ok=False)
        cls.expected = [cls.__module__ + '.' + cls.__qualname__ + '.' + name
                        for name in unittest.defaultTestLoader.getTestCaseNames(cls)]
        cls.started = []; cls.completed = []; cls.stages = []; cls.comparisons = []; cls.controls = []
        cls.finalized = False; cls.source_after = None; cls.source_unchanged = None
        cls.original_retained = None; cls.native = None
        cls.original_paths = sorted((ROOT / 'trillionnium/crates/trnm-peer-lease').rglob('*.rs')) + [
            ROOT / 'trillionnium/crates/trnm-peer-lease/Cargo.toml', ROOT / 'trillionnium/Cargo.toml', ROOT / 'trillionnium/Cargo.lock']
        cls.paths = cls.original_paths + [SOURCE, SOURCE.parent / 'README.md', Path(__file__),
            ROOT / 'hia/tests/peer_lease_original.rs', ROOT / 'hia/tests/peer_lease_native.py',
            ROOT / 'hia/tests/native_support.py', ROOT / 'hia/tools/toolchain.py', ROOT / 'hia/components.json',
            ROOT / 'hia/src/crypto/sha256_stream.hepta', ROOT / 'hia/src/codec/json_primitives.hepta',
            ROOT / 'hia/toolchain.lock.json', ROOT / 'hia/qualification/compiler-binding.json']
        cls.source_before = cls.identities(cls.paths)
        cls.report()
        cls.build_original()
        cls.native = PeerLeaseNative()
        binding = json.loads((ROOT / 'hia/qualification/compiler-binding.json').read_bytes())
        if (cls.native.receipt['compiler_sha256'] != binding['compiler_sha256']
                or cls.native.receipt['claims']['fallback_used'] is not False
                or cls.native.receipt['chain_migration']['backend'] != 'selfhost'):
            raise AssertionError('Peer-lease values did not use the pinned actual native compiler')
        (cls.output / 'peer-values-native.so').write_bytes(cls.native.library.read_bytes())
        (cls.output / 'native-build.json').write_text(json.dumps(cls.native.receipt, indent=2) + '\n')
        cls.report()

    @classmethod
    def stage(cls, name, argv, *, required=True, timeout=180):
        started = time.monotonic()
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout, check=False)
        (cls.output / (name + '.stdout.raw')).write_bytes(result.stdout)
        (cls.output / (name + '.stderr.raw')).write_bytes(result.stderr)
        cls.stages.append({'name': name, 'argv': argv, 'returncode': result.returncode,
            'required_build_stage': required, 'wall_seconds': time.monotonic() - started,
            'stdout': cls.identity(result.stdout), 'stderr': cls.identity(result.stderr)})
        cls.report()
        if required and result.returncode:
            raise AssertionError((name, result.returncode, result.stderr.decode(errors='replace')[-6000:]))
        return result

    @classmethod
    def build_original(cls):
        rustc = shutil.which('rustc'); cargo = shutil.which('cargo')
        if not rustc or not cargo:
            raise RuntimeError('The complete actual Rust toolchain is mandatory')
        selected = cls.stage('rustc-sysroot', [rustc, '--print', 'sysroot'])
        sysroot = selected.stdout.decode().strip()
        if not Path(sysroot).is_absolute():
            raise AssertionError('Rust sysroot is not exact and absolute')
        compiler = (Path(sysroot) / 'bin/rustc').resolve(strict=True)
        cls.stage('rustc-version', [str(compiler), '-Vv'])
        (cls.output / 'rustc-identity.json').write_text(json.dumps({'path': str(compiler),
            **cls.identity(compiler.read_bytes())}, indent=2) + '\n')
        retained = os.environ.get('HIA_PEER_LEASE_ORIGINAL_BASELINE')
        if retained:
            directory = Path(retained).resolve(strict=True)
            execution = json.loads((directory / 'execution.json').read_bytes())
            before = json.loads((directory / 'source-before.json').read_bytes())
            after = json.loads((directory / 'source-after.json').read_bytes())
            stdout = (directory / 'stdout.raw').read_bytes(); stderr = (directory / 'stderr.raw').read_bytes()
            validate_retained_observation(execution, before, after, cls.identities(cls.original_paths), stdout, stderr)
            for name in ('execution.json', 'stdout.raw', 'stderr.raw', 'source-before.json', 'source-after.json'):
                shutil.copy2(directory / name, cls.output / ('original-retained.' + name))
            provenance = json.loads((directory / 'provenance.json').read_bytes())
            if (provenance.get('schema') != 'trnm.peer-lease.retained-execution-provenance.v1'
                    or not provenance.get('host') or not provenance.get('job_id')
                    or provenance.get('complete_unfiltered_original_passed') != (execution['returncode'] == 0)):
                raise AssertionError('External retained execution has no complete host provenance')
            required = {'execution.json', 'stdout.raw', 'stderr.raw', 'source-before.json', 'source-after.json',
                        'retained-report.json', 'retained-manifest.json', 'original-binaries.json',
                        'terminal-job-status.json', 'process-request.json'}
            if not required.issubset(provenance.get('files', {})):
                raise AssertionError('External retained provenance is missing original evidence')
            for name, wanted in provenance['files'].items():
                if Path(name).name != name or cls.identity((directory / name).read_bytes()) != wanted:
                    raise AssertionError('External retained provenance file differs: ' + name)
                shutil.copy2(directory / name, cls.output / ('original-retained.' + name))
            report = json.loads((directory / 'retained-report.json').read_bytes())
            binaries = json.loads((directory / 'original-binaries.json').read_bytes())
            terminal = json.loads((directory / 'terminal-job-status.json').read_bytes())
            process = json.loads((directory / 'process-request.json').read_bytes())
            if (report['original_execution'] != execution or report['original_binaries'] != binaries
                    or not binaries or report['source_unchanged'] is not True
                    or report['complete_source_unchanged'] is not True
                    or report['complete_unfiltered_original_passed'] != (execution['returncode'] == 0)
                    or terminal['job_id'] != provenance['job_id']
                    or terminal['terminal_publication_confirmed'] is not True
                    or terminal['output_complete'] is not True or terminal['timed_out'] is not False
                    or (terminal['exit_code'] == 0) != (execution['returncode'] == 0)
                    or process['host'] != provenance['host']):
                raise AssertionError('External retained execution identities disagree')
            shutil.copy2(directory / 'provenance.json', cls.output / 'original-retained.provenance.json')
            cls.original_retained = {**execution, 'reused_exact_observation': True,
                'stdout': cls.identity(stdout), 'stderr': cls.identity(stderr), 'provenance': provenance,
                'observation_host_is_current_test_host': False}
            # A remote test binary is not relabelled as a local build or loaded
            # across toolchains. Build the full identical crate locally for the
            # real API adapter; the separate unfiltered execution stays intact.
            target_dir = cls.output / 'original-target'
            result = cls.stage('original-local-build', [cargo, 'test', '--locked', '--no-run',
                '--manifest-path', str(ROOT / 'trillionnium/Cargo.toml'), '-p', 'trnm-peer-lease',
                '--all-features', '--target-dir', str(target_dir), '--message-format=json'], timeout=300)
            build_stdout = result.stdout
        else:
            target_dir = cls.output / 'original-target'
            argv = [cargo, 'test', '--locked', '--no-fail-fast', '--manifest-path', str(ROOT / 'trillionnium/Cargo.toml'),
                '-p', 'trnm-peer-lease', '--all-features', '--target-dir', str(target_dir), '--message-format=json',
                '--', '--test-threads=1']
            result = cls.stage('original-retained', argv, required=False, timeout=600)
            stdout, stderr = result.stdout, result.stderr
            cls.original_retained = {'argv': argv, 'returncode': result.returncode,
                'reused_exact_observation': False, 'stdout': cls.identity(stdout), 'stderr': cls.identity(stderr),
                'observation_host_is_current_test_host': True}
            build_stdout = stdout
        rows = []
        for line in build_stdout.decode().splitlines():
            if line.startswith('{'):
                rows.append(json.loads(line))
        artifacts = [row for row in rows if row.get('reason') == 'compiler-artifact']
        libraries = [name for row in artifacts if row['target']['name'] == 'trnm_peer_lease'
                     for name in row['filenames'] if name.endswith('.rlib')]
        if len(libraries) != 1:
            raise AssertionError('The complete unchanged original crate rlib is not unique')
        binary_dir = cls.output / 'original-binaries'; binary_dir.mkdir()
        binaries = []
        for source in sorted({row['executable'] for row in artifacts if row.get('executable')} | set(libraries)):
            path = Path(source); raw = path.read_bytes(); ident = cls.identity(raw)
            name = path.name + '-' + ident['sha256'][:16]
            shutil.copy2(path, binary_dir / name)
            binaries.append({'original_path': source, 'path': 'original-binaries/' + name, **ident})
        (cls.output / 'original-binaries.json').write_text(json.dumps(binaries, indent=2) + '\n')
        cls.oracle = cls.output / 'peer-lease-original'
        cls.stage('adapter-build', [str(compiler), '--edition=2021', '-O', str(ROOT / 'hia/tests/peer_lease_original.rs'),
            '-L', 'dependency=' + str(Path(libraries[0]).parent), '--extern', 'trnm_peer_lease=' + libraries[0], '-o', str(cls.oracle)])
        cls.report()

    @classmethod
    def report(cls):
        files = {p.relative_to(cls.output).as_posix(): cls.identity(p.read_bytes())
                 for p in sorted(cls.output.rglob('*')) if p.is_file() and p != cls.output / 'report.json'
                 and 'original-target' not in p.relative_to(cls.output).parts}
        complete = (cls.started == cls.expected and [r['test'] for r in cls.completed] == cls.expected
                    and all(r['status'] == 'PASS' for r in cls.completed))
        failed = any(r['status'] != 'PASS' for r in cls.completed)
        failed |= any(r['required_build_stage'] and r['returncode'] != 0 for r in cls.stages)
        failed |= any(not r['match'] for r in cls.comparisons) or cls.source_unchanged is False
        original_passed = cls.original_retained is not None and cls.original_retained['returncode'] == 0
        final = 'FAIL' if failed or cls.original_retained is not None and not original_passed else 'PASS' if cls.finalized and complete and cls.source_unchanged else 'INCOMPLETE'
        value = {'schema': 'trnm.hia.peer-lease-values-development.v1', 'status': final,
            'finalized': cls.finalized, 'expected_tests': cls.expected, 'started_tests': cls.started,
            'completed_tests': cls.completed, 'complete_successful_roster': complete,
            'source_inputs': cls.source_before, 'source_after': cls.source_after, 'source_unchanged': cls.source_unchanged,
            'stages': cls.stages, 'original_retained': cls.original_retained, 'original_retained_passed': original_passed,
            'comparisons': cls.comparisons, 'native_operation_count': sum(r['operations'] for r in cls.comparisons),
            'all_recorded_comparisons_match': all(r['match'] for r in cls.comparisons),
            'controls': cls.controls, 'files': files, 'whole_package_retired': False,
            'durable_journal_owner_implemented': False, 'unix_authority_implemented': False,
            'native_core_authentication_implemented': False, 'production_activation': False}
        (cls.output / 'report.json').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

    def run(self, result=None):
        result = self.defaultTestResult() if result is None else result
        cls = type(self); cls.started.append(self.id()); cls.report()
        returned = super().run(result)
        cls.completed.append(actual_test_outcome(self, result)); cls.report()
        return returned

    @classmethod
    def tearDownClass(cls):
        try:
            cls.source_after = cls.identities(cls.paths); cls.source_unchanged = cls.source_before == cls.source_after
            cls.finalized = True; cls.report()
            if not cls.source_unchanged:
                raise AssertionError('Peer-lease source changed during actual qualification')
        finally:
            if cls.native: cls.native.close()
            if cls.temporary: cls.temporary.cleanup()

    def compare(self, commands, label):
        return self.compare_raw(session(commands), label, len(commands))

    def compare_raw(self, raw, label, count=0):
        original = subprocess.run([str(self.oracle)], input=raw, capture_output=True, timeout=120, check=False)
        self.assertEqual(original.returncode, 0, original.stderr)
        self.assertEqual(original.stderr, b'')
        self.assertGreaterEqual(len(original.stdout), 8)
        status_code = struct.unpack_from('<Q', original.stdout)[0]
        expected = original.stdout[8:]
        capacity = max(45, len(expected) + 17)
        observed = self.native.sessions([(raw, capacity)], timeout=180)['cases'][0]
        wanted = expected + b'\xa5' * (capacity - len(expected)) if status_code == 0 else b'\xa5' * capacity
        match = observed['value'] == status_code and observed['output'] == wanted
        index = len(type(self).comparisons)
        for suffix, data in [('input.bin', raw), ('original.stdout.raw', original.stdout), ('original.stderr.raw', original.stderr), ('native.bin', observed['output'])]:
            (self.output / f'comparison-{index:04d}.{suffix}').write_bytes(data)
        type(self).comparisons.append({'index': index, 'label': label, 'operations': count, 'match': match,
            'input': self.identity(raw), 'original': self.identity(original.stdout), 'native': self.identity(observed['output']),
            'original_status': status_code, 'native_status': observed['value']})
        self.report()
        self.assertTrue(match, (label, type(self).comparisons[-1]))
        return decode_reply(expected) if status_code == 0 else status_code

    def test_all_public_values_methods_clone_drop_and_isolation(self):
        commands = [operation(0, scope()), operation(1, token()), operation(2, namespace()),
            operation(3, words(3) + digest(2) + words(1)), operation(4, frame()), operation(5, target()),
            operation(6, words(6, 1) + digest(11)), operation(7, status(4)), operation(8, projection()),
            operation(9, ' run\0🙂 '.encode()), operation(10, b'abc')]
        commands += [operation(11, words(i)) for i in range(1, 10)]
        commands += [operation(12, words(9)), operation(14, words(9, 10)), operation(13, words(9)),
            operation(11, words(9)), operation(11, words(10)), operation(15, words(1, 4)),
            operation(1, token(handle=3)), operation(6, words(5, 1) + digest(1)),
            operation(0, scope(remote=digest(19))), operation(11, words(11)), operation(11, words(1))]
        rows = self.compare(commands, 'all-values-and-private-lifetimes')
        self.assertEqual(rows[21][2], words(1)); self.assertEqual(rows[23][1], 64)
        self.assertEqual(rows[25][2], words(1)); self.assertEqual(rows[26][1], 65)
        self.assertEqual(rows[27][1], 65)

    def test_constructor_errors_preserve_original_order_and_handles(self):
        zero = digest(0); commands = []
        for opts in [{'local': zero}, {'remote': zero}, {'peer': zero}, {'remote': digest(1)},
                     {'local': zero, 'remote': zero, 'peer': zero}]:
            commands.append(operation(0, scope(**opts)))
        commands.append(operation(0, scope(epoch=0)))
        for opts in [{'session_id': zero}, {'generation': 0}, {'record_hash': zero},
                     {'session_id': zero, 'generation': 0, 'record_hash': zero}]:
            commands.append(operation(1, token(**opts)))
        for opts in [{'run': zero}, {'network': zero}, {'session_id': zero}, {'generation': 0},
                     {'kind': 0}, {'length': BODY_MAX + 1}, {'fingerprint': zero},
                     {'run': zero, 'session_id': zero, 'generation': 0, 'kind': 0, 'length': MAX, 'fingerprint': zero},
                     {'length': MAX, 'fingerprint': zero}]:
            commands.append(operation(4, frame(**opts)))
        for field in ['local', 'peer', 'run', 'network']:
            commands.append(operation(2, namespace(**{field: zero})))
        for opts in [{'index': 0}, {'record_hash': zero}, {'remote': zero}, {'session_id': zero},
                     {'generation': 0}, {'kind': 0}, {'length': BODY_MAX + 1}, {'fingerprint': zero}]:
            commands.append(operation(5, target(**opts)))
        commands += [operation(5, target(index=MAX, generation=MAX, sequence=MAX, kind=255, length=BODY_MAX)),
            operation(6, words(2, 0) + zero), operation(6, words(2, 0) + digest(2)),
            operation(6, words(2, 1) + zero), operation(6, words(2, MAX) + digest(2)),
            operation(1, token(generation=MAX, expiry=MAX)),
            operation(4, frame(generation=MAX, sequence=MAX, kind=255, length=BODY_MAX)),
            *[operation(11, words(i)) for i in range(1, 6)]]
        rows = self.compare(commands, 'original-error-precedence-and-counter-domains')
        self.assertEqual(rows[5][2], words(1))

    def test_all_identity_bits_and_opaque_value_fields(self):
        commands = []; handle = 1
        for offset in [0, 32, 64]:
            for bit in range(256):
                data = bytearray(scope(epoch=MAX)); data[offset + bit // 8] ^= 1 << (bit % 8)
                commands += [operation(0, bytes(data)), operation(11, words(handle)),
                             operation(12, words(handle)), operation(14, words(handle, handle + 1))]
                handle += 2
        self.compare(commands, 'each-scope-identity-bit-and-clone')
        commands = [operation(0, scope())]; handle = 2
        for bit in range(64):
            commands += [operation(1, token(generation=1 << bit, expiry=MAX ^ (1 << bit))), operation(11, words(handle))]
            handle += 1
            commands += [operation(4, frame(generation=1 << bit, sequence=MAX ^ (1 << bit))), operation(11, words(handle))]
            handle += 1
        self.compare(commands, 'every-u64-generation-sequence-expiry-bit')

    def test_scope_order_uses_original_tuple_order(self):
        values = [scope(local=digest(a), remote=digest(b), peer=digest(c), direction=direction, epoch=epoch)
                  for a, b, c, direction, epoch in [(1, 2, 255, 1, 256), (1, 2, 0x80, 2, 0),
                    (1, 2, 3, 1, 1), (1, 2, 3, 1, 256), (1, 2, 3, 1, MAX),
                    (1, 2, 4, 1, 256), (1, 3, 1, 1, 0), (2, 1, 1, 1, 0)]]
        commands = [operation(0, value) for value in values]
        commands += [operation(15, words(a, b)) for a in range(1, 9) for b in range(1, 9)]
        self.compare(commands, 'derived-scope-Ord-all-tuple-priorities')

    def test_run_hash_utf8_and_exact_body_size_boundary(self):
        values = ['', '\0', ' ', 'a\0b', 'é', 'e\u0301', '负责👩🏽‍💻', '\U0010ffff', 'λ' * 8193]
        commands = [operation(9, value.encode()) for value in values]
        for length in [0, 1, 31, 55, 56, 63, 64, 65, 127, 128, 129, 4095, 4096]:
            commands.append(operation(10, bytes(i % 256 for i in range(length))))
        self.compare(commands, 'hash-domain-byte-length-utf8-and-sha-padding')
        for length in [BODY_MAX, BODY_MAX + 1]:
            body = (bytes(range(256)) * ((length + 255) // 256))[:length]
            rows = self.compare([operation(10, body)], 'exact-body-bound-' + str(length))
            self.assertEqual(rows[0][1], 0 if length == BODY_MAX else 11)

    def test_projection_getters_all_statuses_and_truth_boundary(self):
        commands = []; handle = 1
        for kind in range(1, 5):
            for high in [False, True]:
                wire = status(kind, count=MAX if high else 0, head_count=MAX if high else 0,
                    temporary=(1 << 32) - 1 if high else 0, head=digest(255 if high else 0),
                    revision=MAX if high else 0, ack=digest(255 if high else 0), acknowledgement=digest(255 if high else 0))
                commands += [operation(7, wire), operation(11, words(handle)),
                    operation(8, projection(kind, status_bytes=wire)), operation(11, words(handle + 1))]
                handle += 2
        self.compare(commands, 'four-status-variants-all-getters-ordinary-zero-namespace')

    def test_projection_exact_digest_mutations_and_parse_error_order(self):
        raw = projection(); commands = []
        for bit in range(len(raw) * 8):
            changed = bytearray(raw); changed[bit // 8] ^= 1 << (bit % 8)
            commands.append(operation(8, bytes(changed)))
        self.compare(commands, 'every-projection-bit-is-bound')
        prefix = raw[:-32]; commands = []
        for length in [0, 1, 205, 206, 210, 211, 214, 215, 218, 219, 222, 223, 242, 243, 250, 251, 282, 283, 314, 315, 316, 317, 318, 319, 480, 481]:
            p = (prefix + b'x' * 512)[:length]
            commands.append(operation(8, seal_projection(p)))
        for offset, data in [(0, b'X'), (8, b'\0'), (9, b'\1'), (116, b'\0'), (116, b'\3'),
            (44, bytes(8)), (52, bytes(32)), (84, bytes(32)), (117, bytes(32)), (149, bytes(8)),
            (165, b'\0'), (166, struct.pack('>I', BODY_MAX + 1)), (170, bytes(32)),
            (202, b'\0'), (202, b'\5'), (315, b'\0'), (316, b'\1'), (317, b'\1')]:
            p = bytearray(prefix); p[offset:offset + len(data)] = data
            commands.append(operation(8, seal_projection(p)))
        for kind in [1, 2, 3]:
            p = bytearray(prefix); p[202] = kind
            for length in range(206, 246):
                commands.append(operation(8, seal_projection(bytes(p[:length]))))
        self.compare(commands, 'rehashed-invalid-projection-exact-field-error-order')

    def test_deterministic_private_owner_histories(self):
        rng = random.Random(0x4D040001)
        for iteration in range(8):
            commands = []
            for i in range(200):
                op = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15])
                h = rng.randrange(0, i + 5)
                if op == 0: data = scope(local=digest(rng.randrange(4)), remote=digest(rng.randrange(4)), epoch=rng.choice([0, 1, MAX]))
                elif op == 1: data = token(handle=h, generation=rng.choice([0, 1, MAX]))
                elif op == 2: data = namespace(epoch=rng.choice([0, MAX]))
                elif op == 3: data = words(h) + digest(rng.randrange(4)) + words(rng.choice([1, 2]))
                elif op == 4: data = frame(handle=h, length=rng.choice([0, BODY_MAX, BODY_MAX + 1]))
                elif op == 5: data = target(index=rng.choice([0, 1, MAX]))
                elif op == 6: data = words(h, rng.choice([0, 1, MAX])) + digest(rng.randrange(3))
                elif op == 7: data = status(rng.randrange(1, 5))
                elif op >= 14: data = words(h, rng.randrange(0, i + 5))
                else: data = words(h)
                commands.append(operation(op, data))
            self.compare(commands, 'mixed-private-owner-history-' + str(iteration))

    def test_malformed_typed_transports_and_output_capacity(self):
        good = session([operation(0, scope()), operation(11, words(1))])
        bad = [good[:i] for i in range(16)] + [good[:-1], good + b'x']
        for offset in [0, 8, 16, 24, 128]:
            changed = bytearray(good); changed[offset:offset + 8] = words(MAX); bad.append(bytes(changed))
        bad += [session([operation(0, scope(direction=0))]), session([operation(0, scope(direction=3))]),
                session([operation(4, frame(kind=256))]), session([operation(5, target(length=1 << 32))]),
                session([operation(7, words(1, 0, 0, 1 << 32))]), session([operation(16)]),
                *[session([operation(0, scope()), operation(9, value)]) for value in
                  [b'\xff', b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\xc2']]]
        for index, data in enumerate(bad):
            self.assertEqual(self.compare_raw(data, 'malformed-' + str(index)), 100)
        original = subprocess.run([str(self.oracle)], input=good, capture_output=True, timeout=60, check=True)
        needed = len(original.stdout) - 8
        cases = [(good, size) for size in [0, 1, 31, 32, 39, needed - 1, needed]]
        observed = self.native.sessions(cases)['cases']
        for (data, size), row in zip(cases, observed):
            self.assertEqual(row['value'], 0 if size == needed else 102)
            self.assertEqual(row['output'], original.stdout[8:] if size == needed else b'\xa5' * size)
        self.controls.append({'name': 'exact-output-capacity', 'cases': len(cases), 'complete': True}); self.report()

    def test_actual_allocation_failures_cleanup_every_private_owner(self):
        compiler = shutil.which('cc')
        if not compiler: raise RuntimeError('Actual allocator fault interposition compiler is required')
        source = self.output / 'allocator-fault.c'; source.write_text(FAULT_SOURCE)
        library = self.output / 'allocator-fault.so'
        self.stage('allocator-fault-build', [compiler, '-shared', '-fPIC', '-O2', str(source), '-o', str(library)])
        raw = session([operation(0, scope()), operation(12, words(1)), operation(8, projection()),
                       operation(11, words(3)), operation(13, words(1)), operation(11, words(2))])
        base = self.native.sessions([(raw, 4096, 0)], fault_library=library)['cases'][0]
        self.assertEqual(base['value'], 0); self.assertEqual(base['allocator']['calls'], 4)
        self.assertEqual(base['allocator']['alive'], 0); self.assertEqual(base['allocator']['invalid'], 0)
        cases = [(raw, 4096, fail) for fail in range(1, 6)]
        observed = self.native.sessions(cases, fault_library=library)['cases']
        for (_, size, fail), row in zip(cases, observed):
            self.assertEqual(row['value'], 103 if fail <= 4 else 0)
            self.assertEqual(row['allocator']['denied'], int(fail <= 4))
            self.assertEqual(row['allocator']['alive'], 0); self.assertEqual(row['allocator']['invalid'], 0)
            if fail <= 4: self.assertEqual(row['output'], b'\xa5' * size)
        self.controls.append({'name': 'all-private-allocations-actual-null', 'baseline': base['allocator'],
                              'observations': [row['allocator'] for row in observed], 'complete': True}); self.report()

    def test_reporter_refuses_failed_skipped_subtest_and_setup(self):
        def passed(case): pass
        def failure(case): case.fail('reporter negative control')
        def subtest(case):
            with case.subTest(value=1): case.fail('subtest negative control')
        def skipped(case): case.skipTest('skip negative control')
        def setup_error(case): raise RuntimeError('setup negative control')
        for method, setup, expected in [(passed, None, 'PASS'), (failure, None, 'FAIL'),
                (subtest, None, 'FAIL'), (skipped, None, 'FAIL'), (passed, setup_error, 'FAIL')]:
            attrs = {'test_probe': method}
            if setup: attrs['setUp'] = setup
            case = type('ReportProbe', (unittest.TestCase,), attrs)('test_probe')
            result = unittest.TestResult(); case.run(result)
            self.assertEqual(actual_test_outcome(case, result)['status'], expected)
        self.controls.append({'name': 'actual-unittest-outcome-negative-controls', 'cases': 5, 'complete': True}); self.report()

    def test_retained_execution_binding_rejects_changed_source_stream_and_filters(self):
        # This negative control checks the same admission function used by an
        # external observation. Its valid example is protocol framing only;
        # it never substitutes for the mandatory actual original execution.
        before = {'original.rs': self.identity(b'original')}
        stdout = b'actual raw output'; stderr = b''
        execution = {'argv': ['/absolute/cargo', 'test', '--offline', '--locked', '--no-fail-fast',
            '--manifest-path', '/absolute/trillionnium/Cargo.toml', '-p', 'trnm-peer-lease', '--all-features',
            '--target-dir', '/absolute/target', '--message-format=json', '--', '--test-threads=1'],
            'source_unchanged': True, 'retained_original_tests_not_filtered': True, 'timed_out': False,
            'returncode': 0, 'stdout': self.identity(stdout), 'stderr': self.identity(stderr)}
        validate_retained_observation(execution, before, before, before, stdout, stderr)
        probes = []
        for flag in ['--lib', '--bins', '--tests', '--no-default-features']:
            changed = copy.deepcopy(execution); changed['argv'].insert(9, flag); probes.append(changed)
        changed = copy.deepcopy(execution); changed['argv'] += ['--skip', 'unix']; probes.append(changed)
        for name, value in [('timed_out', True), ('source_unchanged', False), ('returncode', None)]:
            changed = copy.deepcopy(execution); changed[name] = value; probes.append(changed)
        for changed in probes:
            with self.assertRaises(ValueError):
                validate_retained_observation(changed, before, before, before, stdout, stderr)
        for current, out, err in [({}, stdout, stderr), ({'original.rs': self.identity(b'changed')}, stdout, stderr),
                                   (before, stdout + b'x', stderr), (before, stdout, stderr + b'x')]:
            with self.assertRaises(ValueError):
                validate_retained_observation(execution, before, before, current, out, err)
        self.controls.append({'name': 'retained-original-exact-source-command-stream-admission',
                              'negative_cases': len(probes) + 4, 'complete': True}); self.report()

    def test_z_complete_unchanged_original_retained_suite(self):
        self.assertIsNotNone(self.original_retained)
        self.assertEqual(self.original_retained['returncode'], 0,
            'The actual complete original peer-lease retained suite failed; raw stdout/stderr remain in the evidence. Native value comparisons cannot replace this gate.')


if __name__ == '__main__':
    unittest.main()
