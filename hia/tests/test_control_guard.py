"""Execute the HIA-owned local guard against the full unchanged Rust guard.

The concrete local Ed25519 provider is a new, explicitly named profile. Neither
adapter accepts a caller's verification boolean or trusts a signature digest in
place of a signature. The original crate supplies guard policy and receipt
hashing; its original crypto crate supplies strict verification and test signing.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_control_plane import (
    MASK, MIN128, MAX128, action, action_digest, bound, completed_test_result,
    digest, domain_hash, forbidden, placement, plan, receipt, u64,
)
from hia.tests.test_ed25519 import L, P, little, sign

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'hia/src/control_plane/guard.hepta'
SIGNER_DOMAIN = b'trnm.control.local-ed25519-provider.signer.v1'
SIGNATURE_DOMAIN = b'trnm.control.local-ed25519-provider.signature.v1'
MESSAGE_DOMAIN = b'trnm.control.local-ed25519-provider.plan.v1'
SEED = bytes(range(32))
PUBLIC, _ = sign(SEED, b'')
SIGNER = domain_hash(SIGNER_DOMAIN, PUBLIC)


def signed_plan(*, seed=SEED, message_domain=MESSAGE_DOMAIN, **fields):
    public, _ = sign(seed, b'')
    fields.setdefault('signer', domain_hash(SIGNER_DOMAIN, public))
    value = plan(**fields)
    _, signature = sign(seed, message_domain + value[280:312])
    value = value[:248] + domain_hash(SIGNATURE_DOMAIN, signature) + value[280:]
    return value, signature


def evaluation(value, *, height=100, configuration=None, invariant=None,
               governance=None, determinism=None):
    configuration = digest(9) if configuration is None else configuration
    invariant = digest(10) if invariant is None else invariant
    return (u64(height) + configuration + invariant + u64(int(governance is not None))
            + (b'' if governance is None else governance) + u64(int(determinism is not None))
            + (b'' if determinism is None else determinism) + value)


def session(evaluations=(), *, bounds=None, signatures=(), public=PUBLIC,
            graph=None, contracts=None, generation=7):
    bounds = [bound()] if bounds is None else bounds
    graph = digest(2) if graph is None else graph
    contracts = digest(3) if contracts is None else contracts
    return (b'NCPG0001' + graph + contracts + u64(generation) + public
            + u64(len(bounds), len(signatures), len(evaluations))
            + b''.join(u64(len(value)) + value for value in bounds)
            + b''.join(signatures)
            + b''.join(u64(len(value)) + value for value in evaluations))


def decode_output(raw):
    if len(raw) < 16:
        raise AssertionError('No complete guard output header')
    size, count = struct.unpack_from('<2Q', raw)
    if size != len(raw):
        raise AssertionError('Guard output size differs')
    position, rows = 16, []
    for _ in range(count):
        category, error, length = struct.unpack_from('<3Q', raw, position)
        position += 24
        value = raw[position:position + length]
        if len(value) != length:
            raise AssertionError('Incomplete guard receipt')
        rows.append((category, error, value))
        position += length
    if position != len(raw):
        raise AssertionError('Trailing guard output')
    return rows


def decisions(value):
    count = struct.unpack_from('<Q', value, 144)[0]
    if len(value) != 184 + count * 48:
        raise AssertionError('Receipt result extent differs')
    return [struct.unpack_from('<2Q', value, 216 + i * 48) for i in range(count)]


def finalized_report(expected, started, completed):
    return (started == expected and [row['method'] for row in completed] == expected
            and len(completed) == len(expected) and all(row['passed'] for row in completed))


class ControlGuardNative(unittest.TestCase):
    @classmethod
    def blob(cls, raw):
        raw = bytes(raw)
        digest_value = hashlib.sha256(raw).hexdigest()
        target = cls.directory / 'blobs' / digest_value
        if target.exists():
            if target.read_bytes() != raw:
                raise AssertionError('Blob hash identity differs')
        else:
            with target.open('xb') as stream:
                stream.write(raw)
        return {'path': 'blobs/' + digest_value, 'size': len(raw), 'sha256': digest_value}

    @classmethod
    def arguments(cls, values):
        if values is None:
            return None
        return [cls.blob(value) if isinstance(value, (bytes, bytearray)) else value for value in values]

    @classmethod
    def process(cls, command, raw=b'', *, timeout=60, kind='build'):
        command = [str(part) for part in command]
        row = {'test': cls.current_test, 'kind': kind, 'command': command,
               'stdin': cls.blob(raw), 'timeout': timeout}
        try:
            result = subprocess.run(command, input=raw, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            row.update({'returncode': None, 'failure': 'timeout',
                        'stdout': cls.blob(error.stdout or b''), 'stderr': cls.blob(error.stderr or b'')})
            cls.processes.append(row)
            cls.flush_processes()
            raise
        except OSError as error:
            row.update({'returncode': None, 'failure': repr(error),
                        'stdout': cls.blob(b''), 'stderr': cls.blob(b'')})
            cls.processes.append(row)
            cls.flush_processes()
            raise
        row.update({'returncode': result.returncode, 'stdout': cls.blob(result.stdout),
                    'stderr': cls.blob(result.stderr)})
        if Path(command[0]).is_file():
            row['executable_sha256'] = hashlib.sha256(Path(command[0]).read_bytes()).hexdigest()
        cls.processes.append(row)
        cls.flush_processes()
        if result.returncode:
            raise AssertionError((command, result.returncode, result.stdout, result.stderr))
        return result

    @classmethod
    def flush_processes(cls):
        (cls.directory / 'processes.json').write_text(json.dumps(cls.processes, indent=2) + '\n')

    @classmethod
    def build_original(cls):
        directory = cls.directory / 'original'
        directory.mkdir()
        sha = os.environ.get('HIA_CONTROL_PLANE_SHA2')
        if sha:
            sha = Path(sha).resolve(strict=True)
            deps = sha.parent
            dependencies = {'sha2': sha}
            for name in ['anyhow', 'ed25519_dalek', 'hex', 'trnm_protocol', 'zeroize', 'ml_dsa', 'serde_json']:
                candidates = list(deps.glob('lib' + name + '-*.rlib'))
                if len(candidates) != 1:
                    raise AssertionError(('Original dependency must be unique', name, candidates))
                dependencies[name] = candidates[0]
        else:
            target = Path(cls.temporary.name) / 'cargo-target'
            result = cls.process(['cargo', 'build', '--locked', '--manifest-path', ROOT / 'trillionnium/Cargo.toml',
                '-p', 'trnm-control-plane', '-p', 'trnm-crypto-primitives', '--target-dir', target,
                '--message-format=json'], timeout=180)
            names = {'sha2', 'anyhow', 'ed25519_dalek', 'hex', 'trnm_protocol', 'zeroize', 'ml_dsa', 'serde_json'}
            candidates = {name: set() for name in names}
            for line in result.stdout.splitlines():
                event = json.loads(line)
                name = event.get('target', {}).get('name')
                if event.get('reason') != 'compiler-artifact' or name not in names:
                    continue
                if name == 'sha2' and not event['package_id'].endswith('sha2@0.10.9'):
                    continue
                candidates[name].update(Path(value) for value in event['filenames'] if value.endswith('.rlib'))
            if any(len(values) != 1 for values in candidates.values()):
                raise AssertionError(('Original Cargo dependency selection is ambiguous', candidates))
            dependencies = {name: next(iter(values)) for name, values in candidates.items()}
            sha = dependencies['sha2']
            deps = sha.parent
        (directory / 'dependencies.json').write_text(json.dumps({name: {
            'path': str(path), 'size': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in dependencies.items()}, indent=2))
        rustc = shutil.which('rustc')
        if not rustc:
            raise AssertionError('Actual rustc is required; no reference skip is permitted')
        cls.process([rustc, '-Vv'])
        common = [rustc, '--edition=2021', '-L', 'dependency=' + str(deps)]
        crypto = directory / 'libtrnm_crypto_primitives.rlib'
        external = []
        for name, path in dependencies.items():
            external += ['--extern', name + '=' + str(path)]
        cls.process(common + ['-O', '--crate-name', 'trnm_crypto_primitives', '--crate-type', 'rlib',
            str(ROOT / 'trillionnium/crates/trnm-crypto-primitives/src/lib.rs'), *external, '-o', str(crypto)], timeout=180)
        original = ROOT / 'trillionnium/crates/trnm-control-plane/src/lib.rs'
        library = directory / 'libtrnm_control_plane.rlib'
        sha_args = ['--extern', 'sha2=' + str(sha)]
        cls.process(common + ['-O', '--crate-name', 'trnm_control_plane', '--crate-type', 'rlib',
            str(original), *sha_args, '-o', str(library)], timeout=180)
        tests = directory / 'original-tests'
        cls.process(common + ['--test', str(original), *sha_args, '-o', str(tests)], timeout=180)
        result = cls.process([tests, '--test-threads=1'], timeout=60, kind='retained-tests')
        if b'test result: ok. 5 passed; 0 failed;' not in result.stdout:
            raise AssertionError('The complete original retained control-plane roster did not pass')
        cls.original = directory / 'original'
        cls.process(common + ['-O', str(ROOT / 'hia/tests/control_guard_original.rs'),
            '--extern', 'trnm_control_plane=' + str(library), '--extern', 'trnm_crypto_primitives=' + str(crypto),
            '-o', str(cls.original)], timeout=180)
        cls.signer = directory / 'rust-crypto-reference'
        cls.process(common + ['-O', str(ROOT / 'hia/tests/rust_crypto_reference.rs'),
            '--extern', 'trnm_crypto_primitives=' + str(crypto), '-o', str(cls.signer)], timeout=180)

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-control-guard-')
        cls.addClassCleanup(cls.temporary.cleanup)
        configured = os.environ.get('HIA_CONTROL_GUARD_OUTPUT')
        cls.directory = Path(configured) if configured else Path(cls.temporary.name) / 'evidence'
        cls.directory.mkdir(parents=True, exist_ok=False)
        (cls.directory / 'blobs').mkdir()
        cls.current_test = 'setUpClass'
        cls.expected = unittest.defaultTestLoader.getTestCaseNames(cls)
        cls.started, cls.completed = [], []
        cls.processes, cls.native_observations, cls.comparisons = [], [], []
        from hia.tools.toolchain import checked_source
        _, composed, _, _, dependencies = checked_source(SOURCE)
        paths = {path.relative_to(ROOT).as_posix() for path, _ in dependencies}
        paths.update(['hia/tests/test_control_guard.py', 'hia/tests/control_guard_original.rs',
            'hia/tests/control_guard_alloc.c', 'hia/tests/native_support.py', 'hia/tests/test_control_plane.py',
            'hia/tests/test_ed25519.py', 'hia/tests/rust_crypto_reference.rs', 'hia/tools/toolchain.py',
            'hia/toolchain.lock.json', 'trillionnium/crates/trnm-control-plane/src/lib.rs',
            'trillionnium/crates/trnm-control-plane/Cargo.toml', 'trillionnium/Cargo.lock', 'trillionnium/Cargo.toml',
            'trillionnium/crates/trnm-crypto-primitives/Cargo.toml'])
        paths.update(path.relative_to(ROOT).as_posix() for path in
                     (ROOT / 'trillionnium/crates/trnm-crypto-primitives/src').rglob('*.rs'))
        cls.source_before = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in sorted(paths)}
        (cls.directory / 'run-start.json').write_text(json.dumps({'schema': 'trnm.hia.control-guard.run-start.v1',
            'expected_test_methods': cls.expected, 'source_before': cls.source_before, 'finalized': False}, indent=2))
        (cls.directory / 'composed.hepta').write_bytes(composed)
        cls.native = NativeModule(SOURCE, byte_exports=('f0',))
        cls.addClassCleanup(cls.native.close)
        shutil.copy2(cls.native.library, cls.directory / 'guard.so')
        (cls.directory / 'native-build.json').write_text(json.dumps(cls.native.receipt, indent=2))
        original_call_many = cls.native.call_many

        def captured(cases, *, timeout=30):
            cases = list(cases)
            observed = original_call_many(cases, timeout=timeout)
            for (function, arguments), result in zip(cases, observed):
                cls.native_observations.append({'test': cls.current_test, 'function': function,
                    'arguments': cls.arguments(arguments), 'status': result.status, 'value': result.value,
                    'returncode': result.returncode, 'abi_status': result.abi_status,
                    'observed_arguments': cls.arguments(result.arguments), 'stderr': cls.blob(result.stderr.encode())})
            return observed
        cls.native.call_many = captured
        cls.build_original()

    def setUp(self):
        type(self).current_test = self._testMethodName
        type(self).started.append(self._testMethodName)

    def run(self, result=None):
        result = self.defaultTestResult() if result is None else result
        returned = super().run(result)
        type(self).completed.append({'method': self._testMethodName, **completed_test_result(self, result)})
        return returned

    @classmethod
    def tearDownClass(cls):
        sources = []
        for path, before in cls.source_before.items():
            raw = (ROOT / path).read_bytes()
            sources.append({'source_path': path, 'before_sha256': before, **cls.blob(raw)})
        unchanged = all(item['before_sha256'] == item['sha256'] for item in sources)
        finalized = (cls.started == cls.expected and [row['method'] for row in cls.completed] == cls.expected
                     and len(cls.completed) == len(cls.expected))
        report = {'schema': 'trnm.hia.control-guard.development.v1', 'expected_test_methods': cls.expected,
            'started_test_methods': cls.started, 'completed_test_methods': cls.completed, 'finalized': finalized,
            'result': 'PASS' if unchanged and finalized_report(cls.expected, cls.started, cls.completed) else 'FAIL',
            'source_inputs': sources, 'source_unchanged': unchanged, 'native_observations': cls.native_observations,
            'processes': cls.processes, 'comparisons': cls.comparisons, 'native_calls': len(cls.native_observations),
            'original_comparisons': len(cls.comparisons), 'profile': 'trnm.control.local-ed25519-provider.v1',
            'original_guard_policy': True, 'actual_signature_verification': True,
            'original_production_signature_provider_found': False, 'node_integration_complete': False,
            'whole_package_retired': False}
        (cls.directory / 'observations.json').write_text(json.dumps(report, indent=2) + '\n')
        if not unchanged:
            raise AssertionError('Qualification source changed between build and completed execution')

    def compare(self, frames):
        frames = list(frames)
        wire = b''.join(raw.hex().encode() + b'\n' for raw in frames)
        result = self.process([self.original], wire, kind='guard-oracle')
        expected = []
        for line in result.stdout.splitlines():
            code, output = line.split(b' ', 1)
            expected.append((int(code), b'' if output == b'-' else bytes.fromhex(output.decode())))
        self.assertEqual(len(expected), len(frames))
        for start in range(0, len(frames), 8):
            selected = frames[start:start + 8]
            cases = [('f0', [raw, b'\xa5' * (len(out) + 17),
                       b'\x6d' * (max(140800, 65536 + 3 * len(raw)) + 13)])
                     for raw, (_, out) in zip(selected, expected[start:start + 8])]
            observed = self.native.call_many(cases, timeout=60)
            for raw, expected_row, got in zip(selected, expected[start:start + 8], observed):
                # Actual outputs are already retained by captured(), even if this fails.
                type(self).comparisons.append({'test': self._testMethodName, 'input': self.blob(raw),
                    'oracle_code': expected_row[0], 'oracle_output': self.blob(expected_row[1]),
                    'native_code': got.value, 'native_status': got.status})
                got.require_returned()
                self.assertEqual(got.value, expected_row[0])
                self.assertEqual(got.arguments[0], raw)
                self.assertEqual(got.arguments[1], expected_row[1] + b'\xa5' * 17)
                self.assertEqual(got.arguments[2][-13:], b'\x6d' * 13)
        return expected

    def outcomes(self, frame):
        [(code, output)] = self.compare([frame])
        self.assertEqual(code, 0)
        return decode_output(output)

    def test_constructor_validation_first_error_and_duplicate_order(self):
        rows = [(session(bounds=[]), 0), (session(bounds=[], public=bytes(32)), 0)]
        for keyword in ('graph', 'contracts'):
            rows.append((session(bounds=[bound(minimum=2, maximum=1)], **{keyword: bytes(32)}), 12))
        rows.append((session(generation=0, bounds=[bound(minimum=2, maximum=1)]), 12))
        for generation in (1, MASK):
            rows.append((session(generation=generation), 0))
        numbers = [MIN128, -(1 << 64), -1, 0, 1, 1 << 64, MAX128]
        for low, high in itertools.product(numbers, repeat=2):
            rows.append((session(bounds=[bound(minimum=low, maximum=high)]), 10 if low > high else 0))
        for fields in ({'module':64}, {'module':65535}, {'parameter':b''}, {'parameter':b'p'*129}, {'cls':1}, {'cls':2}):
            rows.append((session(bounds=[bound(**fields)]), 10))
        rows += [(session(bounds=[bound(), bound()]), 11),
                 (session(bounds=[bound(), bound(minimum=-5, maximum=1)]), 11),
                 (session(bounds=[bound(), bound(minimum=2, maximum=1)]), 10),
                 (session(bounds=[bound(), bound(), bound(minimum=2, maximum=1)]), 11),
                 (session(bounds=[bound(), bound(module=5)]), 0),
                 (session(bounds=[bound(parameter=b'\0\xff'), bound(parameter=b'\0\xff\0')]), 0)]
        results = self.compare(raw for raw, _ in rows)
        self.assertEqual([code for code, _ in results], [code for _, code in rows])
        for (code, output) in results:
            self.assertEqual(output, u64(16, 0) if code == 0 else b'')

    def test_full_i128_boundaries_and_per_action_rejections(self):
        numbers = [MIN128, MIN128+1, -(1 << 64), -1, 0, 1, (1 << 64)-1, 1 << 64, MAX128]
        plans = [signed_plan(actions=[action(value=value)]) for value in numbers]
        sigs = [item[1] for item in plans]
        for low, high in itertools.combinations_with_replacement([MIN128, -(1 << 64), -1, 0, 1, 1 << 64, MAX128], 2):
            rows = self.outcomes(session([evaluation(item[0]) for item in plans], signatures=sigs,
                                        bounds=[bound(minimum=low, maximum=high)]))
            self.assertTrue(all((category, error) == (0, 0) for category, error, _ in rows))
            self.assertEqual([decisions(value) for _, _, value in rows],
                             [[(0, 0)] if low <= value <= high else [(1, 20)] for value in numbers])
            self.assertEqual([struct.unpack_from('<Q', value, 136)[0] for _, _, value in rows],
                             [int(low <= value <= high) for value in numbers])
        actions = [action(parameter=b'a', value=0), action(parameter=b'b', value=-1),
                   action(parameter=b'\0\xff\x80', value=MIN128), action(module=5, parameter=b'a', value=MAX128)]
        value, signature = signed_plan(actions=actions)
        [(category, error, result)] = self.outcomes(session([evaluation(value)], signatures=[signature], bounds=[
            bound(parameter=b'a', minimum=0, maximum=0), bound(parameter=b'\0\xff\x80', minimum=MIN128, maximum=MAX128),
            bound(module=5, parameter=b'a', minimum=0, maximum=0)]))
        self.assertEqual((category, error), (0, 0))
        self.assertEqual(decisions(result), [(0, 0), (1, 19), (0, 0), (1, 20)])
        self.assertEqual([result[184+i*48:216+i*48] for i in range(4)], [action_digest(row) for row in actions])

    def test_shape_precedes_signature_and_ignored_optional_evidence(self):
        governance = digest(1) + u64(MASK) + digest(2) + digest(3)
        determinism = b''.join(digest(i) for i in range(5))
        cases = [([],8), ([action(parameter=b'')],9), ([action(parameter=b'p'*129)],9),
                 ([action(module=64)],9), ([action(cls=1)],25), ([action(cls=2)],25),
                 ([action(),action()],24), ([placement()],25)]
        cases += [([forbidden(kind)],17) for kind in range(10)]
        cases.append(([action(parameter=i.to_bytes(2,'big')) for i in range(129)],8))
        frames, errors = [], []
        for actions, error in cases:
            value = plan(actions=actions, signer=SIGNER)
            for gov, det in itertools.product((None, governance), (None, determinism)):
                frames.append(session([evaluation(value, governance=gov, determinism=det)], signatures=[]))
                errors.append(error)
        for (_, raw), error in zip(self.compare(frames), errors):
            self.assertEqual(decode_output(raw), [(1,error,b'')])
        good, signature = signed_plan()
        rows = self.outcomes(session([evaluation(good, governance=gov, determinism=det)
            for gov, det in itertools.product((None, bytes(104)), (None, bytes(160)))], signatures=[signature]))
        self.assertTrue(all(row == rows[0] for row in rows))
        self.assertEqual(rows[0][:2], (0,0))

    def test_signature_binding_new_domains_and_real_verification(self):
        value, signature = signed_plan()
        frames = [session([evaluation(value)], signatures=[signature]),
                  session([evaluation(value)], signatures=[])]
        expected = [(0,0),(2,2)]
        wrong_signer, sig = signed_plan(signer=digest(99))
        frames.append(session([evaluation(wrong_signer)], signatures=[sig]));expected.append((2,1))
        for domain in (b'', b'trnm.control.optimization-plan.v1', MESSAGE_DOMAIN+b'\0', SIGNER_DOMAIN):
            bad, sig = signed_plan(message_domain=domain)
            frames.append(session([evaluation(bad)], signatures=[sig]));expected.append((2,3))
        bad = value[:248] + domain_hash(SIGNATURE_DOMAIN+b'\0',signature) + value[280:]
        frames.append(session([evaluation(bad)], signatures=[signature]));expected.append((2,2))
        bad, sig = signed_plan(signer=domain_hash(SIGNER_DOMAIN+b'\0',PUBLIC))
        frames.append(session([evaluation(bad)], signatures=[sig]));expected.append((2,1))
        # The plan's canonical digest intentionally excludes signature_digest;
        # the provider resolves it to actual privately retained signature bytes.
        bad = value[:248] + digest(55) + value[280:]
        self.assertEqual(value[280:312],bad[280:312])
        frames.append(session([evaluation(bad)], signatures=[signature]));expected.append((2,2))
        for index in range(64):
            modified = bytearray(signature);modified[index] ^= 1 << (index % 8)
            modified = bytes(modified)
            bad = value[:248] + domain_hash(SIGNATURE_DOMAIN,modified) + value[280:]
            frames.append(session([evaluation(bad)], signatures=[modified]));expected.append((2,3))
        for (_, output), pair in zip(self.compare(frames), expected):
            [row] = decode_output(output)
            self.assertEqual(row[:2], pair)
        # A signed canonical hash is bound to every original public plan fact.
        for field in range(6):
            fields = [digest(i) for i in range(1,7)];fields[field] = digest(99)
            bad = plan(fields=fields,signer=SIGNER,signature=domain_hash(SIGNATURE_DOMAIN,signature))
            self.assertEqual(self.outcomes(session([evaluation(bad)],signatures=[signature]))[0][:2],(2,3))

    def test_strict_key_R_S_rejections_are_signature_errors(self):
        value, signature = signed_plan()
        frames=[]
        for public in (bytes(32),little(1),little(P),little(P-1),little(1|(1<<255))):
            bad = plan(signer=domain_hash(SIGNER_DOMAIN,public),signature=domain_hash(SIGNATURE_DOMAIN,signature))
            frames.append(session([evaluation(bad)],signatures=[signature],public=public))
        for modified in (little(P)+signature[32:],little(1)+signature[32:],bytes(32)+signature[32:],
                         signature[:32]+little(L),signature[:32]+bytes([255])*32):
            bad=value[:248]+domain_hash(SIGNATURE_DOMAIN,modified)+value[280:]
            frames.append(session([evaluation(bad)],signatures=[modified]))
        for _, output in self.compare(frames):
            self.assertEqual(decode_output(output),[(2,3,b'')])

    def test_complete_error_order_inclusive_height_and_u64_overflow(self):
        value, signature = signed_plan()
        configurations=[({'graph':digest(99)}, {'height':0,'configuration':bytes(32)},13),
                        ({'contracts':digest(99)}, {},13),
                        ({'generation':MASK}, {'height':0,'configuration':bytes(32)},26),
                        ({'generation':8}, {'height':0,'configuration':bytes(32)},14),
                        ({}, {'height':99,'configuration':bytes(32)},15),
                        ({}, {'height':201,'invariant':bytes(32)},15),
                        ({}, {'configuration':bytes(32)},16), ({}, {'invariant':bytes(32)},16)]
        for constructor, facts, error in configurations:
            frame=session([evaluation(value,**facts)],signatures=[signature],**constructor)
            self.assertEqual(self.outcomes(frame),[(1,error,b'')])
            no_signature=session([evaluation(value,**facts)],signatures=[],**constructor)
            self.assertEqual(self.outcomes(no_signature),[(2,2,b'')])
        for height in (100,200):
            self.assertEqual(self.outcomes(session([evaluation(value,height=height)],signatures=[signature]))[0][:2],(0,0))
        exact,sig=signed_plan(generation=MASK,before=MASK,expires=MASK)
        self.assertEqual(self.outcomes(session([evaluation(exact,height=MASK)],signatures=[sig],generation=MASK-1))[0][:2],(0,0))
        invalid,sig=signed_plan(generation=0)
        self.assertEqual(self.outcomes(session([evaluation(invalid)],signatures=[sig],generation=MASK)),[(1,8,b'')])
        bad=value[:280]+bytes(32)+value[312:]
        self.assertEqual(self.outcomes(session([evaluation(bad,height=0)],signatures=[],graph=digest(99),generation=MASK)),[(1,8,b'')])

    def test_private_immutable_generation_and_repeated_receipts(self):
        good, signature = signed_plan()
        future, future_sig = signed_plan(generation=9)
        rejected, rejected_sig = signed_plan(actions=[action(value=MAX128)])
        rows=self.outcomes(session([evaluation(good),evaluation(rejected),evaluation(future),
                                   evaluation(good),evaluation(rejected),evaluation(good)],
            signatures=[signature,future_sig,rejected_sig]))
        self.assertEqual(rows[0],rows[3]);self.assertEqual(rows[0],rows[5]);self.assertEqual(rows[1],rows[4])
        self.assertEqual(rows[2],(1,14,b''));self.assertEqual(decisions(rows[1][2]),[(1,20)])
        self.assertEqual(struct.unpack_from('<Q',rows[0][2],32)[0],8)

    def test_maximum_actions_raw_parameters_and_original_receipt_hash(self):
        actions=[action(module=i%64,parameter=bytes([i])+b'\0\xff'+bytes([255-i])*125,
                        value=MIN128 if i%2 else MAX128) for i in range(128)]
        bounds=[bound(module=i%64,parameter=raw[48:],minimum=MIN128,maximum=MAX128)
                for i,raw in enumerate(actions)]
        value,sig=signed_plan(actions=actions)
        [(category,error,observed)]=self.outcomes(session([evaluation(value)],bounds=bounds,signatures=[sig,sig]))
        self.assertEqual((category,error),(0,0));self.assertEqual(decisions(observed),[(0,0)]*128)
        expected,hashed=receipt([(action_digest(row),0,0) for row in actions],
            generation=8,fields=[value[280:312],digest(2),digest(9),digest(10)])
        self.assertEqual(observed,expected);self.assertEqual(observed[152:184],hashed)

    def test_actual_original_rust_signer_is_accepted(self):
        templates=[];requests=[]
        for i in range(8):
            seed=hashlib.sha256(b'original Rust local guard signer'+u64(i)).digest()
            public,_=sign(seed,b'')
            value=plan(actions=[action(value=32+i)],signer=domain_hash(SIGNER_DOMAIN,public))
            templates.append((seed,public,value))
            requests.append(b'S '+seed.hex().encode()+b' '+(MESSAGE_DOMAIN+value[280:312]).hex().encode()+b'\n')
        result=self.process([self.signer],b''.join(requests),kind='actual-rust-signing')
        lines=result.stdout.splitlines();self.assertEqual(len(lines),len(templates))
        frames=[]
        for line,(seed,public,value) in zip(lines,templates):
            got_public,signature=[bytes.fromhex(part.decode()) for part in line.split()]
            self.assertEqual(got_public,public);self.assertEqual((got_public,signature),sign(seed,MESSAGE_DOMAIN+value[280:312]))
            signed=value[:248]+domain_hash(SIGNATURE_DOMAIN,signature)+value[280:]
            frames.append(session([evaluation(signed)],public=public,signatures=[signature]))
        for _,output in self.compare(frames):self.assertEqual(decode_output(output)[0][:2],(0,0))

    def test_typed_frame_truncation_and_scalar_errors_never_publish(self):
        value,sig=signed_plan()
        raw=session([evaluation(value,governance=bytes(104),determinism=bytes(160))],signatures=[sig])
        frames=[raw[:i] for i in range(len(raw))]+[raw+b'\0']
        for offset in (0,112,120,128,136,144,152,192):
            changed=bytearray(raw);struct.pack_into('<Q',changed,offset,MASK);frames.append(bytes(changed))
        # Constructor payload is fully typed before its business validation.
        changed=bytearray(raw);struct.pack_into('<Q',changed,72,0);changed[-1:]=b'';frames.append(bytes(changed))
        for code,output in self.compare(frames):self.assertEqual((code,output),(100,b''))

    def test_option_and_nested_action_typed_limits(self):
        value,sig=signed_plan()
        raw=session([evaluation(value)],signatures=[sig])
        eval_start=136+8+len(bound())+64+8
        plan_start=eval_start+88
        offsets=[eval_start+72,eval_start+80,plan_start+312,plan_start+320,
                 plan_start+328,plan_start+336,plan_start+344,plan_start+368]
        frames=[]
        for offset in offsets:
            for bad in (MASK,1<<63):
                changed=bytearray(raw);struct.pack_into('<Q',changed,offset,bad);frames.append(bytes(changed))
        for code,output in self.compare(frames):self.assertEqual((code,output),(100,b''))

    def test_output_and_scratch_extent_fail_closed(self):
        value,sig=signed_plan();raw=session([evaluation(value),evaluation(value)],signatures=[sig])
        [(status,expected)]=self.compare([raw]);self.assertEqual(status,0)
        minimum=max(140800,65536+len(raw)*3)
        for output,scratch,error in [(15,minimum,101),(16,minimum,101),(len(expected)-1,minimum,101),
                                     (len(expected),minimum-1,102),(len(expected),0,102)]:
            inputs=[raw,b'\xa5'*output,b'\x6d'*scratch]
            got=self.native.call('f0',inputs).require_returned()
            self.assertEqual(got.value,error);self.assertEqual(got.arguments[0:2],inputs[0:2])
            if error==102:self.assertEqual(got.arguments,inputs)
        got=self.native.call('f0',[raw,bytes(len(expected)),bytes(minimum)]).require_returned()
        self.assertEqual((got.value,got.arguments[1]),(0,expected))

    def test_actual_three_owner_allocation_failures_release_every_owner(self):
        directory=self.directory/'allocator-observer';directory.mkdir()
        source=ROOT/'hia/tests/control_guard_alloc.c';shutil.copy2(source,directory/source.name)
        observer=directory/'observer'
        self.process(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-rdynamic',source,'-ldl','-o',observer])
        value,sig=signed_plan();good=session([evaluation(value)],signatures=[sig])
        [(status,output)]=self.compare([good]);self.assertEqual(status,0)
        specifications=[(good,len(output)+17,fail,103,fail,1) for fail in (1,2,3)]
        specifications += [(good,len(output)+17,0,0,3,0),(good,16,0,101,3,0),
                           (session(bounds=[bound(minimum=2,maximum=1)]),64,0,10,3,0),
                           (session(generation=0),64,0,12,3,0)]
        observations=[]
        for index,(raw,size,fail,status,calls,denied) in enumerate(specifications):
            path=directory/f'case-{index}.bin';path.write_bytes(raw)
            result=self.process([observer,self.directory/'guard.so',path,size,fail],kind='allocator-observation')
            (directory/f'case-{index}.stdout').write_bytes(result.stdout)
            (directory/f'case-{index}.stderr').write_bytes(result.stderr)
            self.assertEqual(len(result.stdout),32+size)
            got,allocated,refused,live=struct.unpack_from('<4Q',result.stdout)
            observations.append({'index':index,'status':got,'calls':allocated,'denied':refused,'live':live})
            self.assertEqual((got,allocated,refused,live),(status,calls,denied,0))
            self.assertEqual(result.stdout[32:],output+b'\xa5'*17 if status==0 else b'\xa5'*size)
        (directory/'observations.json').write_text(json.dumps(observations,indent=2)+'\n')

    def test_reporter_requires_complete_finalized_successful_roster(self):
        class Probe(unittest.TestCase):
            def runTest(self):self.fail('retained negative reporter control')
        failing=Probe();result=unittest.TestResult();failing.run(result)
        checked=completed_test_result(failing,result)
        self.assertFalse(checked['passed']);self.assertEqual(checked['unittest_outcomes']['failures'],1)
        good={'method':'one','passed':True}
        bad={'method':'one','passed':False}
        self.assertTrue(finalized_report(['one'],['one'],[good]))
        for expected,started,completed in [(['one'],[],[]),(['one','two'],['one'],[good]),
                                          (['one'],['one'],[bad]),(['one'],['one','one'],[good,good])]:
            self.assertFalse(finalized_report(expected,started,completed))
        (self.directory/'reporter-controls.json').write_text(json.dumps({'failed_body_result':checked,
            'incomplete_and_duplicate_rosters_rejected':True},indent=2)+'\n')


if __name__ == '__main__':
    unittest.main()
