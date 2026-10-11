"""Complete native zero-suite bytes against the original scalar Python relation.

The three zero-only operations must refuse other canonical material. Generic and
general paired controls accept their actual nonzero operands. No task source,
current-parent admission, hardware speed or hardness is granted by this bridge.
Raw stdout, stderr and every failure remain available, including empty outputs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
import unittest

from contract_wire import H, ROOT
import work_oracle


SOURCE_PATHS = [
    'rust-toolchain.toml', 'trillionnium/Cargo.lock',
    'config/pon/work-profile-v1.json',
    'formal/pon-nakamoto-v1/contract_wire.py',
    'formal/pon-nakamoto-v1/work_oracle.py',
    'formal/pon-nakamoto-v1/test_zero_work.py',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs',
    'trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_io.rs',
    'trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_locality_cost.rs',
    'trillionnium/crates/trnm-pon-node/tests/zero_task_preparation_lifecycle.rs',
]
OPERATIONS = ('generic', 'structured-zero-reference', 'blocked-zero',
              'paired-product', 'blocked-zero-integer-paired')
ZERO_OPERATIONS = ('structured-zero-reference', 'blocked-zero', 'blocked-zero-integer-paired')


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ZeroWorkOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get('TRNM_ZERO_WORK')
        if not binary:
            raise RuntimeError('TRNM_ZERO_WORK must name the freshly built actual pon_zero_io')
        cls.binary = Path(binary).resolve()
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise RuntimeError('The complete zero bridge needs an actual executable, never a skip')
        output = os.environ.get('TRNM_ZERO_WORK_OUTPUT')
        if not output:
            raise RuntimeError('TRNM_ZERO_WORK_OUTPUT must name a fresh retained directory')
        cls.output = Path(output).resolve()
        cls.output.mkdir(parents=True, exist_ok=False)
        cls.observations = []
        cls.before = cls.identity()
        (cls.output / 'identity-before.json').write_text(json.dumps(cls.before, indent=2, sort_keys=True) + '\n')

    @classmethod
    def identity(cls):
        return {'binary': str(cls.binary), 'binary_sha256': sha256(cls.binary),
                'python': sys.version, 'python_executable': sys.executable,
                'source_sha256': {name: sha256(ROOT / name) for name in SOURCE_PATHS},
                'binary_source_binding_requires_actual_build_receipt': True}

    @classmethod
    def tearDownClass(cls):
        after = cls.identity()
        unchanged = after == cls.before
        (cls.output / 'identity-after.json').write_text(json.dumps(after, indent=2, sort_keys=True) + '\n')
        comparisons = sum(row['expected_exit_code'] == 0 for row in cls.observations)
        rejections = sum(row['expected_exit_code'] == 2 for row in cls.observations)
        complete = len(cls.observations) == 88 and comparisons == 28 and rejections == 60
        report = {
            'schema': 'pon-w1-zero-paired-python-native-v1',
            'result': 'PASS' if unchanged and complete and
                      all(row['result'] == 'PASS' for row in cls.observations) else 'FAIL',
            'source_and_binary_unchanged': unchanged,
            'source_before': cls.before, 'source_after': after,
            'native_invocations': len(cls.observations), 'full_proof_byte_comparisons': comparisons,
            'explicit_rejections': rejections, 'observations': cls.observations,
            'timings_are_process_and_io_observations_not_producer_cost': True,
            'work_hardness_accepted': False, 'public_network_accepted': False,
            'independent_institutional_review': False, 'production_activation': False,
        }
        (cls.output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'zero_work_output': str(cls.output), 'result': report['result'],
                          'native_invocations': len(cls.observations)}), flush=True)
        if report['result'] != 'PASS':
            raise AssertionError('Complete zero bridge or source identity failed; retain the FAIL report')

    def case(self, name, data, *, arguments, source_class, expected=None, error=None):
        path = self.output / name
        path.mkdir()
        (path / 'input.bin').write_bytes(data)
        if expected is not None:
            (path / 'python-proof.bin').write_bytes(expected)
        command = [str(self.binary), *arguments]
        record = {'case': name, 'source_class': source_class, 'command': command,
                  'expected_exit_code': 0 if expected is not None else 2,
                  'input_bytes': len(data), 'input_sha256': hashlib.sha256(data).hexdigest(),
                  'timed_out': False, 'timeout_seconds': 30, 'exit_code': None, 'result': 'FAIL'}
        started = time.monotonic_ns()
        with (path / 'input.bin').open('rb') as stdin, \
                (path / 'native-proof.bin').open('xb') as stdout, \
                (path / 'native-stderr.txt').open('xb') as stderr:
            try:
                child = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr,
                                         start_new_session=True)
            except OSError as failure:
                record['launch_error'] = str(failure)
            else:
                try:
                    record['exit_code'] = child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    record['timed_out'] = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                    record['exit_code'] = child.returncode
        record['elapsed_ns_including_process_and_io'] = time.monotonic_ns() - started
        actual = (path / 'native-proof.bin').read_bytes()
        stderr = (path / 'native-stderr.txt').read_bytes()
        record.update(native_stdout_bytes=len(actual), native_stdout_sha256=hashlib.sha256(actual).hexdigest(),
                      native_stderr_sha256=hashlib.sha256(stderr).hexdigest())
        if expected is not None:
            record['python_proof_sha256'] = hashlib.sha256(expected).hexdigest()
            record['expected_ticket'] = H('ticket', data[:32], expected[-32:]).hex()
            record['native_ticket'] = H('ticket', data[:32], actual[-32:]).hex() if len(actual) == 49188 else None
        record['checks'] = {
            'completed': not record['timed_out'] and 'launch_error' not in record,
            'exit_code': record['exit_code'] == record['expected_exit_code'],
            'full_stdout': actual == (expected if expected is not None else b''),
            'stderr': stderr == (b'' if error is None else (error + '\n').encode()),
        }
        record['result'] = 'PASS' if all(record['checks'].values()) else 'FAIL'
        (path / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        self.observations.append(record)
        self.assertEqual(record['result'], 'PASS', f'{name}: inspect retained {path}')

    def test_all_five_complete_zero_producers_match_original_python_bytes(self):
        zero = [0] * work_oracle.CELLS
        task = work_oracle.task_id(zero, zero)
        challenges = [bytes(32), bytes([7]) * 32, bytes([255]) * 32,
                      H('zero-paired-bridge-challenge-v1', task)]
        for index, challenge in enumerate(challenges):
            expected = work_oracle.prove(challenge, zero, zero)
            self.assertEqual(len(expected), 49188)
            data = challenge + work_oracle.field_bytes(zero) * 2
            for operation in OPERATIONS:
                with self.subTest(challenge=index, operation=operation):
                    self.case(f'zero-{index}-{operation}', data, arguments=(operation,), expected=expected,
                              source_class='canonical-zero-arithmetic-control-only')

    def test_general_controls_are_actually_supported_by_generic_and_paired(self):
        q, cells = work_oracle.Q, work_oracle.CELLS
        controls = [('near-q', [q - 1] * cells, [q - 1 - i % 257 for i in range(cells)]),
                    ('one-nonzero', [0] * (cells - 1) + [q - 1], [0] * cells)]
        for name, a, b in controls:
            for index, challenge in enumerate([bytes(32), bytes([255]) * 32]):
                expected = work_oracle.prove(challenge, a, b)
                data = challenge + work_oracle.field_bytes(a) + work_oracle.field_bytes(b)
                for operation in ['generic', 'paired-product']:
                    with self.subTest(control=name, challenge=index, operation=operation):
                        self.case(f'{name}-{index}-{operation}', data, arguments=(operation,), expected=expected,
                                  source_class='canonical-nonzero-arithmetic-control-only')

    def test_zero_only_operations_refuse_complete_canonical_nonzero_material(self):
        cells = work_oracle.CELLS
        for operation in ZERO_OPERATIONS:
            for operand in [0, 1]:
                for position in [0, cells // 2, cells - 1]:
                    a, b = [0] * cells, [0] * cells
                    [a, b][operand][position] = 1
                    data = bytes(32) + work_oracle.field_bytes(a) + work_oracle.field_bytes(b)
                    with self.subTest(operation=operation, operand=operand, position=position):
                        self.case(f'{operation}-nonzero-{operand}-{position}', data, arguments=(operation,),
                                  source_class='unsupported-canonical-material', error='UNSUPPORTED')

    def test_all_operations_check_complete_extent_canonical_fields_and_arguments(self):
        exact = bytes(32 + 2 * work_oracle.CELLS * 4)
        for operation in OPERATIONS:
            for name, data in [('empty', b''), ('short', exact[:-1]), ('extra-byte', exact + b'\0')]:
                with self.subTest(operation=operation, malformed=name):
                    self.case(f'{operation}-{name}', data, arguments=(operation,),
                              source_class='malformed-bridge-input', error='LENGTH')
            for name, offset in [('a-first', 32), ('a-last', 32 + (work_oracle.CELLS - 1) * 4),
                                 ('b-first', 32 + work_oracle.CELLS * 4), ('b-last', len(exact) - 4)]:
                value = bytearray(exact)
                value[offset:offset + 4] = work_oracle.Q.to_bytes(4, 'little')
                with self.subTest(operation=operation, malformed=name):
                    self.case(f'{operation}-field-{name}', bytes(value), arguments=(operation,),
                              source_class='noncanonical-bridge-input', error='WORK')
            self.case(f'{operation}-extra-argument', exact, arguments=(operation, 'extra'),
                      source_class='unrecognized-bridge-operation', error='OPERATION')

    def test_missing_and_unknown_operations_are_errors_with_empty_stdout(self):
        exact = bytes(32 + 2 * work_oracle.CELLS * 4)
        for name, arguments in [('missing', ()), ('unknown', ('unsupported',))]:
            self.case(f'{name}-operation', exact, arguments=arguments,
                      source_class='unrecognized-bridge-operation', error='OPERATION')


def scalar_prefixes(noise: bytes) -> bytes:
    """Original full E/F construction and scalar transcript, without paired factors."""
    if len(noise) != 4 * work_oracle.N * work_oracle.R * 4:
        raise ValueError('four complete 64x8/8x64 noise operands required')
    values = list(struct.unpack('<' + 'I' * (len(noise) // 4), noise))
    if any(value >= work_oracle.Q for value in values):
        raise ValueError('canonical field noise required')
    n, r, q = work_oracle.N, work_oracle.R, work_oracle.Q
    el, er, fl, fr = [values[index * n * r:(index + 1) * n * r] for index in range(4)]
    a, b = work_oracle.mm(el, er, n, r, n), work_oracle.mm(fl, fr, n, r, n)
    words = []
    for bi in range(0, n, r):
        for bj in range(0, n, r):
            cells = [0] * (r * r)
            for bk in range(0, n, r):
                for i in range(r):
                    for j in range(r):
                        position = i * r + j
                        cells[position] = (cells[position] + sum(a[(bi + i) * n + k] * b[k * n + bj + j]
                                                                 for k in range(bk, bk + r))) % q
                        words.append(cells[position])
    return work_oracle.field_bytes(words)


def declared_prefix_noise(case: int) -> bytes:
    """Four explicit arithmetic controls; resealing a zero substitute is not an extreme test."""
    q, size = work_oracle.Q, work_oracle.N * work_oracle.R
    values = []
    for label in range(4):
        for index in range(size):
            if case == 0:
                value = q - 1
            elif case == 1:
                value = 0 if (index + label) % 3 == 0 else q - 1 - index % 17
            elif case == 2:
                value = 0 if label in (0, 3) else q - 1
            elif case == 3:
                value = int.from_bytes(H('zero-paired-prefix-values-v1', bytes([label]),
                                         index.to_bytes(8, 'little'))[:4], 'little') % q
            else:
                raise ValueError('unknown original noise control')
            values.append(value)
    return work_oracle.field_bytes(values)


def verify_prefix_export(source: Path, destination: Path) -> dict:
    """Independently replay all four raw native extreme-prefix exports; never benchmark."""
    destination.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'pon-w1-zero-paired-prefix-python-v1', 'result': 'FAIL', 'cases': [],
              'source_sha256': {name: sha256(ROOT / name) for name in SOURCE_PATHS},
              'synthetic_noise_control_only': True, 'not_a_work_proof': True,
              'work_hardness_accepted': False, 'production_activation': False}
    try:
        names = {f'case-{index}' for index in range(4)}
        if source.is_symlink() or not source.is_dir() or {path.name for path in source.iterdir()} != names:
            raise ValueError('exact four-case native prefix export required')
        for name in sorted(names):
            path = source / name
            files = {'noise-input.bin', 'scalar-prefixes.bin', 'native-prefixes.bin', 'receipt.json'}
            if path.is_symlink() or not path.is_dir() or {file.name for file in path.iterdir()} != files:
                raise ValueError('exact original prefix case files required')
            if any((path / file).is_symlink() or not (path / file).is_file() for file in files):
                raise ValueError('regular original prefix files required')
            before = {file: sha256(path / file) for file in files}
            record = json.loads((path / 'receipt.json').read_text())
            if (type(record) is not dict or set(record) != {'schema', 'case', 'result', 'prefix_words',
                    'input_sha256', 'scalar_sha256', 'native_sha256', 'synthetic_noise_control_only', 'not_a_work_proof'} or
                    record.get('schema') != 'pon-w1-blocked-zero-paired-prefix-observation-v1' or
                    record.get('result') != 'PASS' or type(record.get('case')) is not int or
                    record['case'] != int(name[5:]) or type(record.get('prefix_words')) is not int or
                    record['prefix_words'] != 32768 or record.get('synthetic_noise_control_only') is not True or
                    record.get('not_a_work_proof') is not True or record.get('input_sha256') != before['noise-input.bin'] or
                    record.get('scalar_sha256') != before['scalar-prefixes.bin'] or
                    record.get('native_sha256') != before['native-prefixes.bin']):
                raise ValueError('original prefix receipt and actual bytes must agree')
            noise = (path / 'noise-input.bin').read_bytes()
            if noise != declared_prefix_noise(record['case']):
                raise ValueError('actual noise must equal the declared complete arithmetic control')
            expected = scalar_prefixes(noise)
            output = destination / name
            output.mkdir()
            (output / 'python-prefixes.bin').write_bytes(expected)
            actual = (path / 'native-prefixes.bin').read_bytes()
            scalar = (path / 'scalar-prefixes.bin').read_bytes()
            after = {file: sha256(path / file) for file in files}
            same = expected == actual == scalar and before == after
            observation = {'case': name, 'result': 'PASS' if same else 'FAIL', 'prefix_words': len(expected) // 4,
                           'input_sha256_before': before, 'input_sha256_after': after,
                           'python_sha256': hashlib.sha256(expected).hexdigest()}
            report['cases'].append(observation)
            (output / 'receipt.json').write_text(json.dumps(observation, indent=2, sort_keys=True) + '\n')
            if not same:
                raise ValueError('Python scalar prefix replay differs or the raw source changed')
        report['source_sha256_after'] = {name: sha256(ROOT / name) for name in SOURCE_PATHS}
        if report['source_sha256_after'] != report['source_sha256']:
            raise ValueError('prefix reader source changed')
        report['result'] = 'PASS'
    except Exception as failure:
        report['error'] = f'{type(failure).__name__}: {failure}'
        raise
    finally:
        (destination / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--verify-prefix-export':
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('--verify-prefix-export', type=Path, required=True)
        parser.add_argument('--output', type=Path, required=True)
        arguments = parser.parse_args()
        result = verify_prefix_export(arguments.verify_prefix_export, arguments.output)
        print(json.dumps({'result': result['result'], 'cases': len(result['cases'])}), flush=True)
    else:
        unittest.main(verbosity=2)
