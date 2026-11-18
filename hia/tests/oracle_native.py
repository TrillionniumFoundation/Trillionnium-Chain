"""Evidence transport for actual HIA Oracle machine code; no Oracle semantics."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import traceback

from hia.tests.native_support import MAX_EXTENT, NativeCall

ROOT = Path(__file__).resolve().parents[2]
_REAL_RUN = subprocess.run


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def raw_bytes(value):
    if value is None:
        return b''
    return value.encode() if isinstance(value, str) else bytes(value)


class Evidence:
    def __init__(self, directory, expected):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        (self.directory / 'blobs').mkdir()
        (self.directory / 'processes').mkdir()
        self.expected = list(expected)
        self.started, self.completed = [], []
        self.processes, self.native, self.comparisons = [], [], []
        self.sources, self.artifacts = [], []
        self.current_test = 'setUpClass'
        self.setup_error = None
        self.teardown_checks_passed = False
        self.finalization_error = None
        self.dependency_inputs = []
        self.source_stable = False
        self.finalized = False
        self.write()

    def blob(self, data):
        data = raw_bytes(data)
        key = hashlib.sha256(data).hexdigest()
        path = self.directory / 'blobs' / key
        if not path.exists():
            with path.open('xb') as stream:
                stream.write(data)
        elif path.read_bytes() != data:
            raise AssertionError('CAS blob identity collision')
        return {'path': 'blobs/' + key, 'size': len(data), 'sha256': key}

    def arguments(self, values):
        if values is None:
            return None
        return [self.blob(x) if isinstance(x, (bytes, bytearray)) else x for x in values]

    def snapshot(self, paths):
        for path in sorted(set(map(Path, paths))):
            path = path.resolve(strict=True)
            self.sources.append({'source_path': path.relative_to(ROOT).as_posix(),
                                 'before_sha256': digest(path), **self.blob(path.read_bytes())})
        self.write()

    def artifact(self, path, role):
        path = Path(path)
        self.artifacts.append({'path': path.relative_to(self.directory).as_posix(),
                               'role': role, 'size': path.stat().st_size,
                               'sha256': digest(path)})

    def run(self, argv, *, stage=None, expected_failure=False, **kwargs):
        argv = list(map(str, argv))
        name = stage or 'build-process-' + str(len(self.processes))
        row = {'index': len(self.processes), 'stage': name, 'test': self.current_test,
               'argv': argv, 'timeout': kwargs.get('timeout'), 'expected_failure': expected_failure,
               'stdin': self.blob(kwargs.get('input', b'')), 'returncode': None,
               'failure_kind': None}
        self.processes.append(row)
        stage_file = self.directory / 'processes' / (str(row['index']).zfill(6)+'.json')
        stage_file.write_text(json.dumps(row, indent=2)+'\n')
        check = kwargs.pop('check', False)
        try:
            result = _REAL_RUN(argv, check=False, **kwargs)
            row.update(stdout=self.blob(result.stdout), stderr=self.blob(result.stderr),
                       returncode=result.returncode)
            if result.returncode:
                row['failure_kind'] = 'nonzero-exit'
            if check:
                result.check_returncode()
            return result
        except subprocess.TimeoutExpired as error:
            row.update(stdout=self.blob(error.stdout), stderr=self.blob(error.stderr),
                       failure_kind='timeout', exception_type=type(error).__name__,
                       exception=str(error))
            raise
        except OSError as error:
            row.update(stdout=self.blob(b''), stderr=self.blob(b''), failure_kind='os-error',
                       exception_type=type(error).__name__, exception=str(error), errno=error.errno)
            raise
        finally:
            stage_file.write_text(json.dumps(row, indent=2)+'\n')

    def write(self):
        complete = (self.finalized and self.source_stable and self.teardown_checks_passed
                    and not self.setup_error and not self.finalization_error
                    and self.started == self.expected
                    and [x['method'] for x in self.completed] == self.expected)
        passed = complete and all(x['passed'] for x in self.completed)
        report = {'schema': 'trnm.hia.oracle.development.v1',
                  'result': 'PASS' if passed else 'FAIL' if self.finalized or self.setup_error or self.finalization_error else 'INCOMPLETE',
                  'finalized': passed, 'complete_roster_and_identity_checks': complete,
                  'source_stable': self.source_stable,
                  'teardown_checks_passed': self.teardown_checks_passed,
                  'finalization_error': self.finalization_error,
                  'expected_test_methods': self.expected, 'started_test_methods': self.started,
                  'completed_test_methods': self.completed, 'setup_error': self.setup_error,
                  'source_inputs': self.sources, 'artifacts': self.artifacts,
                  'processes': self.processes, 'native_observations': self.native,
                  'comparisons': self.comparisons,
                  'native_calls': len(self.native), 'original_comparisons': len(self.comparisons),
                  'original_retained_tests_each_profile': 118,
                  'arithmetic_profiles': ['release-wrapping', 'dev-test-checked'],
                  'serde_json_profiles': ['serde_json 1.0.149 default from_slice/to_vec',
                      'serde_json 1.0.149 arbitrary_precision from_slice/to_vec'],
                  'original_retained_tests_total': 472,
                  'whole_package_retired': False, 'node_consumer_integrated': False,
                  'external_network_observed': False, 'whole_chain_native': False}
        (self.directory / 'observations.json').write_text(json.dumps(report, indent=2) + '\n')

    def finish(self):
        try:
            for item in self.sources:
                current = ROOT / item['source_path']
                item['after_sha256'] = digest(current)
                if item['after_sha256'] != item['before_sha256']:
                    raise AssertionError('Source changed during qualification: ' + str(current))
            self.source_stable = bool(self.sources)
            for item in self.artifacts:
                if digest(self.directory/item['path']) != item['sha256']:
                    raise AssertionError('Artifact changed before final report: '+item['path'])
            for item in self.dependency_inputs:
                if digest(item['path']) != item['sha256']:
                    raise AssertionError('Dependency changed before final report: '+item['path'])
            self.finalized = True
        except BaseException:
            self.finalization_error = traceback.format_exc()
            self.teardown_checks_passed = False
            raise
        finally:
            self.write()


class OracleNative:
    """Use native_support's sealed child worker, retaining its actual raw streams."""
    def __init__(self, library, evidence, module):
        self.library = Path(library)
        self.evidence = evidence
        self.module = module
        self.artifact_sha256 = digest(library)

    def call_many(self, cases, *, timeout=30, expected_failure=False):
        if not 0 < timeout <= 60:
            raise ValueError('Native deadline must be in (0,60] seconds')
        cases = list(cases)
        rows = []
        for raw, output, workspace in cases:
            if any(not isinstance(x, bytes) or len(x) > MAX_EXTENT for x in (raw, output, workspace)):
                raise ValueError('Test borrowed buffers exceed native_support 1 MiB transport')
            rows.append({'function': 'f0', 'arguments': [
                {'type': typ, 'bytes': base64.b64encode(value).decode()}
                for typ, value in zip(('readbuf', 'mutbuf', 'mutbuf'), (raw, output, workspace))],
                'returns': ['u32'], 'byte_abi': True})
        request = {'library': str(self.library), 'sha256': self.artifact_sha256,
                   'cases': rows, 'cpu_seconds': max(1, int(timeout))}
        process = None
        try:
            process = self.evidence.run([sys.executable, '-I', '-S', '-B',
                str(ROOT / 'hia/tests/native_support.py'), '--worker'],
                stage='native-' + self.module, expected_failure=expected_failure, input=json.dumps(request).encode(),
                capture_output=True, timeout=timeout, check=False)
            if process.returncode:
                category = 'trapped' if process.returncode in (-signal.SIGABRT, -signal.SIGILL) else 'faulted'
                if len(rows) != 1:
                    category = 'batch_failed'
                answers = [NativeCall(category, process.returncode,
                                      stderr=process.stderr.decode(errors='replace')) for _ in rows]
            else:
                observed = json.loads(process.stdout)
                if (observed.get('artifact_sha256') != self.artifact_sha256
                        or observed.get('host_compiler_modules_loaded') != []
                        or len(observed.get('cases', [])) != len(rows)):
                    raise AssertionError('Native worker identity/complete roster differs')
                answers = []
                for sent, got in zip(rows, observed['cases']):
                    if got.get('function') != 'f0' or len(got.get('arguments', [])) != 3:
                        raise AssertionError('Native worker argument roster differs')
                    values = []
                    for before, after in zip(sent['arguments'], got['arguments']):
                        if after.get('type') != before['type']:
                            raise AssertionError('Native worker argument type differs')
                        actual = base64.b64decode(after['bytes'], validate=True)
                        original = base64.b64decode(before['bytes'])
                        if len(actual) != len(original) or before['type'] == 'readbuf' and actual != original:
                            raise AssertionError('Native worker mutated read-only source or extent')
                        values.append(actual)
                    answers.append(NativeCall('returned', 0, got['value'], got['abi_status'], values,
                                              process.stderr.decode(errors='replace')))
        except subprocess.TimeoutExpired:
            answers = [NativeCall('timeout', None) for _ in rows]
        for sent, answer in zip(cases, answers):
            self.evidence.native.append({'test': self.evidence.current_test, 'module': self.module,
                'function': 'f0', 'artifact_sha256': self.artifact_sha256,
                'process_index': len(self.evidence.processes)-1,
                'arguments': self.evidence.arguments(sent), 'status': answer.status,
                'returncode': answer.returncode, 'abi_status': answer.abi_status, 'value': answer.value,
                'observed_arguments': self.evidence.arguments(answer.arguments),
                'stderr': self.evidence.blob(answer.stderr.encode())})
        return answers
