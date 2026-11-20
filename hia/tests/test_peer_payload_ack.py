"""Fixed recovery ACK codec against the actual retained Rust functions.

This is a codec and existing-value integration qualification. The full original
Peer process gate, Body maximum fixtures and durable ACK owner remain separate.
No filesystem business operation is supplied by this observer.
"""
from __future__ import annotations

import hashlib
import gzip
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

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'hia/platform/peer_payload_recovery'
SOURCE = ROOT / 'hia/src/peer_lease/recovery_ack.hepta'
HOOK = HERE / 'codec_reference_hook.rs'
REFERENCE = ROOT / 'hia/tests/rust_peer_payload_ack_reference.rs'
VALUE_REFERENCE = ROOT / 'hia/tests/peer_lease_original.rs'
VALUE_SOURCE = ROOT / 'hia/src/peer_lease/values.hepta'
PACKAGE = ROOT / 'trillionnium/crates/trnm-peer-lease'
DOMAIN = b'trnm.portable-g1.payload-core-ack.v1'
MAX = (1 << 64) - 1
WORKSPACE = 4352


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def word(value):
    return struct.pack('<Q', value)


def digest(value):
    return bytes((value,)) * 32


def target(index=1, record_hash=None, remote=None, direction=1, session_id=None,
           generation=1, sequence=0, kind=1, size=0, fingerprint=None):
    return (word(index) + (digest(1) if record_hash is None else record_hash)
            + (digest(2) if remote is None else remote) + word(direction)
            + (digest(3) if session_id is None else session_id)
            + word(generation) + word(sequence) + word(kind) + word(size)
            + (digest(4) if fingerprint is None else fingerprint))


def request(namespace=None, value=None, revision=1, ack=None):
    return (word(1) + (digest(5) if namespace is None else namespace)
            + (target() if value is None else value) + word(revision)
            + (digest(6) if ack is None else ack))


def sealed(prefix):
    return prefix + hashlib.sha256(DOMAIN + struct.pack('>Q', len(prefix)) + prefix).digest()


def commands(rows):
    return b'PLV10001' + word(len(rows)) + b''.join(word(op) + word(len(data)) + data
                                                for op, data in rows)


def responses(raw):
    if raw[:8] != b'PLR10001' or len(raw) < 32:
        raise AssertionError('Missing complete peer value transcript')
    count, size, reserved = struct.unpack_from('<QQQ', raw, 8)
    if size != len(raw) or reserved:
        raise AssertionError('Noncanonical peer value transcript')
    result, pos = [], 32
    for _ in range(count):
        op, code, n = struct.unpack_from('<QQQ', raw, pos)
        pos += 24
        data = raw[pos:pos+n]
        if len(data) != n:
            raise AssertionError('Truncated peer value result')
        result.append((op, code, data))
        pos += n
    if pos != len(raw):
        raise AssertionError('Trailing peer value result')
    return result


class PeerPayloadAckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='trnm-peer-ack-')
        cls.output = Path(cls.directory.name)
        if ROOT == cls.output or ROOT in cls.output.parents:
            cls.directory.cleanup()
            raise ValueError('Fresh original build must remain outside the checkout')
        configured = os.environ.get('HIA_RECOVERY_ACK_OUTPUT')
        cls.capture = Path(configured).absolute() if configured else None
        if cls.capture is not None:
            if (not Path(configured).is_absolute() or Path(configured).as_posix() != configured
                    or '..' in cls.capture.parts or any(p.is_symlink() for p in (cls.capture, *cls.capture.parents))
                    or cls.capture.exists() or ROOT == cls.capture or ROOT in cls.capture.parents):
                raise ValueError('ACK observations require a fresh output outside the checkout')
            cls.capture.mkdir(parents=True, mode=0o700)
        cls.stages = []
        cls.compared = cls.independent_hashes = cls.abi = cls.value_pairs = 0
        cls.observed_codes = set()
        cls.modules = []
        cls.native_sources = {}
        cls.native_stream = gzip.open(cls.capture / 'native.jsonl.gz', 'xb') if cls.capture else None
        cls.native_calls = 0
        try:
            cls.original = cls.build_original()
            cls.codec = NativeModule(SOURCE, byte_exports=('f0',))
            cls.modules.append(cls.codec)
            cls.values = NativeModule(VALUE_SOURCE, byte_exports=('f0',))
            cls.modules.append(cls.values)
            for module in cls.modules:
                for row in module.receipt['chain_migration']['inputs']:
                    name = 'hia/' + row['path']
                    raw = (ROOT / name).read_bytes()
                    if sha(raw) != row['sha256']:
                        raise AssertionError('Actual native compiler source changed: ' + name)
                    cls.native_sources[name] = row['sha256']
                    if cls.capture is not None:
                        dest = cls.capture / 'source' / name
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(raw)
            if cls.capture is not None:
                for name, module in (('ack', cls.codec), ('values', cls.values)):
                    (cls.capture / (name + '.so')).write_bytes(module.library.read_bytes())
                    (cls.capture / (name + '.receipt.json')).write_text(json.dumps(module.receipt, sort_keys=True) + '\n')
            cls.valid = cls.reference([request()])[0][1]
            if len(cls.valid) != 188:
                raise AssertionError('Original ACK size changed')
        except BaseException:
            for module in cls.modules:
                module.close()
            if cls.native_stream is not None:
                cls.native_stream.close()
            cls.directory.cleanup()
            raise

    @classmethod
    def stage(cls, label, argv, *, data=None, timeout=60):
        before = len(cls.stages)
        result = subprocess.run(argv, input=data, cwd=ROOT, capture_output=True,
                                timeout=timeout, check=False)
        row = {'label': label, 'argv': list(map(str, argv)), 'returncode': result.returncode,
               'timeout_seconds': timeout, 'stdin_sha256': sha(data or b''),
               'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)}
        cls.stages.append(row)
        if cls.capture is not None:
            directory = cls.capture / 'processes' / f'{before:04d}-{label}'
            directory.mkdir(parents=True)
            for name, raw in [('stdin.raw', data or b''), ('stdout.raw', result.stdout),
                              ('stderr.raw', result.stderr)]:
                (directory / name).write_bytes(raw)
            (directory / 'execution.json').write_text(json.dumps(row, sort_keys=True) + '\n')
        if result.returncode:
            raise AssertionError((label, result.returncode, result.stderr.decode(errors='replace')))
        return result.stdout

    @classmethod
    def build_original(cls):
        from hia.platform.peer_payload.contract import check_environment
        from hia.platform.peer_lease_unix.original_build import PROFILE, cargo_events

        check_environment(os.environ)
        version = cls.stage('rust-version', ['rustc', '-Vv'])
        if b'release: 1.95.0\n' not in version:
            raise AssertionError('Original Rust compiler differs from repository pin')
        inputs = [ROOT / 'trillionnium/Cargo.toml', ROOT / 'trillionnium/Cargo.lock',
                  HOOK, REFERENCE, VALUE_REFERENCE, *sorted(PACKAGE.rglob('*.rs')), PACKAGE / 'Cargo.toml']
        before = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in inputs}
        target_dir = cls.output / 'original-target'
        raw = cls.stage('cargo-original', ['cargo', 'build', '--offline', '--locked',
            '--manifest-path', ROOT / 'trillionnium/Cargo.toml', '-p', 'trnm-peer-lease',
            '--all-features', '--lib', '--target-dir', target_dir, '--message-format=json'], timeout=240)
        events = cargo_events(raw)
        libraries, dependencies, artifact_paths = {}, {}, []
        for event in events:
            for name in event['filenames']:
                path = Path(name)
                if path.suffix != '.rlib':
                    continue
                if not path.is_relative_to(target_dir) or path.is_symlink():
                    raise AssertionError('Original library escaped its fresh Cargo target')
                dependencies[str(path)] = sha(path.read_bytes())
                artifact_paths.append(path)
            name = event['target']['name']
            if name not in {'trnm_peer_lease', 'fs2', 'libc', 'rustix', 'sha2'}:
                continue
            paths = [Path(n) for n in event['filenames'] if n.endswith('.rlib')]
            # This slice runs cargo build, whose unchanged dev profile is
            # distinct from the complete Peer gate's test-only sha2 override.
            expected = PROFILE
            if name in libraries or len(paths) != 1 or event['profile'] != expected:
                raise AssertionError('Original library/profile is missing or ambiguous: ' + name)
            if name == 'trnm_peer_lease' and (event['manifest_path'] != str(PACKAGE / 'Cargo.toml')
                    or set(event['features']) != {'default', 'candidate-recovery-socket'}):
                raise AssertionError('Actual original Peer source/feature graph changed')
            libraries[name] = paths[0]
        if set(libraries) != {'trnm_peer_lease', 'fs2', 'libc', 'rustix', 'sha2'}:
            raise AssertionError('Incomplete original dependency set')
        private = cls.output / 'private-source'
        shutil.copytree(PACKAGE / 'src', private / 'src')
        appended = {
            'src/payload_recovery.rs': b'\n' + HOOK.read_bytes(),
            'src/lib.rs': b'\npub use payload_recovery::qualification_recovery_ack_codec_v1;\n',
        }
        instrumentation = {}
        for path in sorted((private / 'src').rglob('*.rs')):
            relative = path.relative_to(private).as_posix()
            original = (PACKAGE / relative).read_bytes()
            if path.read_bytes() != original:
                raise AssertionError('Original copy differs before the append-only hook')
            changed = original + appended.get(relative, b'')
            path.write_bytes(changed)
            instrumentation[relative] = {'original_sha256': sha(original), 'observed_sha256': sha(changed),
                                         'original_bytes': len(original), 'appended_bytes': len(changed)-len(original)}
        common = ['rustc', '--edition=2021', '--deny=warnings', '-C', 'opt-level=0',
                  '-C', 'debuginfo=2', '-C', 'debug-assertions=yes', '-C', 'overflow-checks=yes']
        for p in sorted({p.parent for p in artifact_paths}):
            common += ['-L', 'dependency=' + str(p)]
        private_lib = cls.output / 'liback_original.rlib'
        external = []
        for name in ('fs2', 'libc', 'rustix', 'sha2'):
            external += ['--extern', name + '=' + str(libraries[name])]
        cls.stage('rustfmt-adapters', ['rustfmt', '--edition', '2021', '--check', HOOK, REFERENCE])
        cls.stage('private-original-library', [*common, '--crate-name', 'trnm_peer_lease',
            '--crate-type', 'rlib', '--cfg', 'feature="default"', '--cfg', 'feature="candidate-recovery-socket"',
            *external, private / 'src/lib.rs', '-o', private_lib])
        cls.oracle = cls.output / 'ack-original'
        cls.value_oracle = cls.output / 'values-original'
        cls.stage('ack-adapter', [*common, '--extern', 'trnm_peer_lease=' + str(private_lib),
                                 REFERENCE, '-o', cls.oracle])
        cls.stage('value-adapter', [*common, '--extern', 'trnm_peer_lease=' + str(libraries['trnm_peer_lease']),
                                   VALUE_REFERENCE, '-o', cls.value_oracle])
        if any(sha((ROOT / p).read_bytes()) != h for p, h in before.items()):
            raise AssertionError('Original sources changed during the fresh build')
        if any(sha(Path(p).read_bytes()) != h for p, h in dependencies.items()):
            raise AssertionError('Original Cargo dependencies changed during observer compilation')
        if cls.capture is not None:
            for path in inputs:
                dest = cls.capture / 'source' / path.relative_to(ROOT)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(path.read_bytes())
            for path in [*artifact_paths, private_lib, cls.oracle, cls.value_oracle]:
                dest = cls.capture / 'original-artifacts' / path.name
                dest.parent.mkdir(exist_ok=True)
                if dest.exists() and dest.read_bytes() != path.read_bytes():
                    raise AssertionError('Ambiguous retained original artifact filename')
                dest.write_bytes(path.read_bytes())
        return {'sources': before, 'instrumentation': instrumentation, 'dependencies': dependencies,
                'original_functions_replaced': False, 'fresh_cargo_build': True,
                'complete_original_tests_rerun_by_this_codec_slice': False,
                'crate_sha256': sha(libraries['trnm_peer_lease'].read_bytes()),
                'private_crate_sha256': sha(private_lib.read_bytes()),
                'adapter_sha256': sha(cls.oracle.read_bytes()), 'value_adapter_sha256': sha(cls.value_oracle.read_bytes())}

    @classmethod
    def tearDownClass(cls):
        stable = all(sha((ROOT / p).read_bytes()) == h
                     for p, h in {**cls.original['sources'], **cls.native_sources}.items())
        if cls.native_stream is not None:
            cls.native_stream.close()
        report = {'schema': 'trnm.hia.payload-recovery-ack-codec.v1', 'source_inputs_stable': stable,
                  'original_native_pairs': cls.compared, 'independent_sha256_checks': cls.independent_hashes,
                  'abi_controls': cls.abi, 'native_value_integration_pairs': cls.value_pairs,
                  'observed_returns': sorted(cls.observed_codes), 'original': cls.original,
                  'native_source_inputs': cls.native_sources,
                  'native': {str(module.source.relative_to(ROOT)): {
                      'source_sha256': sha(module.source.read_bytes()), 'artifact_sha256': module.artifact_sha256,
                      'compiler_sha256': module.receipt['compiler_sha256']} for module in cls.modules},
                  'stages': cls.stages, 'whole_recovery_owner_qualified': False,
                  'body_store_qualified': False, 'production_activation': False,
                  'actual_native_calls': cls.native_calls,
                  'native_observations_sha256': sha((cls.capture / 'native.jsonl.gz').read_bytes()) if cls.capture else None}
        if cls.capture is not None:
            (cls.capture / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True))
        for module in cls.modules:
            module.close()
        cls.directory.cleanup()
        if not stable:
            raise AssertionError('Original source identity changed during the codec tests')

    @classmethod
    def reference(cls, raws):
        raw = cls.stage('original-cases', [cls.oracle], data=b''.join(r.hex().encode()+b'\n' for r in raws))
        lines = raw.splitlines()
        if len(lines) != len(raws):
            raise AssertionError('Original codec did not complete every requested case')
        answers = []
        for line in lines:
            code, sep, value = line.partition(b' ')
            if not sep:
                raise AssertionError('Malformed original codec observation')
            answers.append((int(code), bytes.fromhex(value.decode())))
        return answers

    @classmethod
    def invoke(cls, cases, *, module=None):
        module = cls.codec if module is None else module
        results = module.call_many(cases, timeout=60)
        if cls.native_stream is not None:
            def encoded(values):
                return [{'bytes_hex': bytes(value).hex()} if isinstance(value, (bytes, bytearray))
                        else {'scalar': value} for value in values]
            for (function, args), result in zip(cases, results):
                row = {'artifact_sha256': module.artifact_sha256, 'function': function,
                       'before': encoded(args), 'status': result.status,
                       'returncode': result.returncode, 'value': result.value,
                       'abi_status': result.abi_status, 'stderr': result.stderr,
                       'after': encoded(result.arguments) if result.arguments is not None else None}
                cls.native_stream.write((json.dumps(row,sort_keys=True)+'\n').encode())
        cls.native_calls += len(results)
        return results

    def compare(self, raws):
        for start in range(0, len(raws), 96):
            batch = raws[start:start+96]
            original = self.reference(batch)
            actual = self.invoke([('f0', [raw, b'\xa5'*229, b'\x5a'*(WORKSPACE+33)]) for raw in batch])
            for raw, (code, payload), result in zip(batch, original, actual):
                result.require_returned()
                expected = word(len(payload))+payload+b'\xa5'*(221-len(payload)) if code == 0 else b'\xa5'*229
                with self.subTest(input_sha256=sha(raw), size=len(raw)):
                    self.assertEqual(result.value, code)
                    self.assertEqual(result.arguments[0], raw)
                    self.assertEqual(result.arguments[1], expected)
                    self.assertEqual(result.arguments[2][WORKSPACE:], b'\x5a'*33)
                    if code == 100 or len(raw) >= 8 and raw[:8] == word(2) and len(raw) != 196:
                        self.assertEqual(result.arguments[2], b'\x5a'*(WORKSPACE+33))
                    if not code and raw[:8] == word(1):
                        self.assertEqual(payload, sealed(payload[:156]))
                        type(self).independent_hashes += 1
                type(self).compared += 1
                type(self).observed_codes.add(code)

    def test_typed_encoding_preserves_full_fields_without_new_validation(self):
        base = request()
        rows = [base, request(namespace=bytes(32), value=target(index=0, record_hash=bytes(32),
                 remote=bytes(32), session_id=bytes(32), generation=0, kind=0, size=0xffffffff,
                 fingerprint=bytes(32)), revision=0, ack=bytes(32))]
        for position in range(8, len(base)):
            for value in (0, 1, 127, 128, 255):
                rows.append(base[:position]+bytes((value,))+base[position+1:])
        for value in (0, 1, 2, (1 << 32)-1, 1 << 32, 1 << 63, MAX):
            rows += [request(value=target(index=value, generation=value, sequence=value), revision=value),
                     request(value=target(direction=value, kind=value, size=value))]
        rng = random.Random(907170)
        for _ in range(128):
            t = target(index=rng.getrandbits(64), record_hash=rng.randbytes(32), remote=rng.randbytes(32),
                direction=rng.randrange(1,3), session_id=rng.randbytes(32), generation=rng.getrandbits(64),
                sequence=rng.getrandbits(64), kind=rng.randrange(256), size=rng.getrandbits(32),
                fingerprint=rng.randbytes(32))
            rows.append(request(namespace=rng.randbytes(32), value=t, revision=rng.getrandbits(64), ack=rng.randbytes(32)))
        self.compare(rows)

    def test_decode_every_byte_tamper_truncation_and_exact_end(self):
        rows = [word(2)+self.valid[:n] for n in range(188)]
        rows += [word(2)+self.valid+bytes(n) for n in (1,2,3,4,7,8,32,188,1024)]
        for position in range(188):
            for bit in range(8):
                raw = bytearray(self.valid);raw[position] ^= 1 << bit
                rows.append(word(2)+raw)
        self.compare(rows)

    def test_reauthenticated_headers_and_semantic_fields_match_original(self):
        rows = [word(2)+self.valid]
        for position in range(12):
            for value in (0,1,127,128,255):
                raw = bytearray(self.valid[:156]);raw[position] = value
                rows.append(word(2)+sealed(raw))
        for start, end in ((12,44),(44,52),(52,84),(84,116),(116,124),(124,156)):
            for byte in (0,1,255):
                raw = bytearray(self.valid[:156]);raw[start:end] = bytes((byte,))*(end-start)
                rows.append(word(2)+sealed(raw))
        raw = bytearray(self.valid[:156]);raw[12:116] = bytes(104)
        rows.append(word(2)+sealed(raw))
        self.compare(rows)

    def test_existing_native_value_owner_feeds_the_original_ack_codec(self):
        requests = [request(), request(namespace=bytes(32), value=target(index=MAX, direction=2,
            generation=MAX, sequence=MAX, kind=255, size=8388608), revision=MAX, ack=digest(255))]
        for byte in range(1,9):
            requests.append(request(namespace=digest(byte), value=target(index=byte, record_hash=digest(byte),
                remote=digest(byte+1), direction=1+byte%2, session_id=digest(byte+2), generation=byte,
                sequence=MAX-byte, kind=byte, size=byte, fingerprint=digest(byte+3)), revision=byte, ack=digest(byte+4)))
        for raw in requests:
            t = raw[40:216]
            session = commands([(5,t),(6,word(1)+raw[216:256]),(11,word(1)),(11,word(2))])
            original = self.stage('original-value-session', [self.value_oracle], data=session)
            self.assertEqual(original[:8], word(0))
            original = original[8:]
            result = self.invoke([('f0', [session, b'\xa5'*1024, b'\x5a'*17])], module=self.values)[0].require_returned()
            self.assertEqual(result.value,0)
            self.assertEqual(result.arguments[1], original+b'\xa5'*(1024-len(original)))
            self.assertEqual(result.arguments[2], b'\x5a'*17)
            rows = responses(original)
            self.assertEqual(rows[-1][:2], (11,0))
            acknowledgement = rows[-1][2]
            self.assertEqual(acknowledgement[:8],word(6))
            self.assertEqual(acknowledgement[8:],raw[40:256])
            self.compare([word(1)+raw[8:40]+acknowledgement[8:]])
            type(self).value_pairs += 1

    def test_capacity_workspace_and_error_precedence_preserve_caller_output(self):
        fixtures = [request(), word(2)+self.valid]
        for raw in fixtures:
            code,payload = self.reference([raw])[0]
            self.assertEqual(code,0)
            calls = [('f0',[raw,b'\xa5'*n,b'\x5a'*(WORKSPACE+33)])
                     for n in range(len(payload)+10)]
            for n,result in enumerate(self.invoke(calls)):
                result.require_returned()
                self.assertEqual(result.value,0 if n >= len(payload)+8 else 102)
                expected = word(len(payload))+payload+b'\xa5'*(n-len(payload)-8) if n >= len(payload)+8 else b'\xa5'*n
                self.assertEqual(result.arguments[1],expected)
                self.assertEqual(result.arguments[2][WORKSPACE:],b'\x5a'*33)
                type(self).abi += 1
            sizes = (0,1,1208,1312,1536,2048,3072,4096,4295,WORKSPACE-1,WORKSPACE,WORKSPACE+1)
            results = self.invoke([('f0',[raw,b'\xa5'*229,b'\x5a'*n]) for n in sizes])
            for n,result in zip(sizes,results):
                result.require_returned()
                self.assertEqual(result.value,101 if n < WORKSPACE else 0)
                if n < WORKSPACE:
                    self.assertEqual(result.arguments[1],b'\xa5'*229)
                    self.assertEqual(result.arguments[2],b'\x5a'*n)
                type(self).abi += 1
        malformed = [bytes(n) for n in range(8)] + [word(v) for v in (0,3,MAX)]
        malformed += [request()[:n] for n in range(8,256)] + [request()+b'\0']
        for result in self.invoke([('f0',[raw,b'\xa5'*3,b'']) for raw in malformed]):
            result.require_returned()
            self.assertEqual(result.value,100)
            self.assertEqual(result.arguments[1],b'\xa5'*3)
            type(self).abi += 1
        raw = bytearray(self.valid);raw[155] ^= 1
        sizes = (0,1,183,184,229)
        for n,result in zip(sizes,self.invoke([('f0',[word(2)+raw,b'\xa5'*n,b'\x5a'*WORKSPACE]) for n in sizes])):
            result.require_returned()
            self.assertEqual(result.value,3)
            self.assertEqual(result.arguments[1],b'\xa5'*n)
            type(self).abi += 1


if __name__ == '__main__':
    unittest.main()
