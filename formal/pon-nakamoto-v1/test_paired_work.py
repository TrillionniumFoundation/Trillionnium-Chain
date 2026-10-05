"""Complete native paired/maintenance bytes against the existing scalar Python relation.

Fixed genesis maintenance is the sole policy material here. Near-q, hash-dense,
and one-zero inputs are canonical arithmetic controls, not current-parent task
admission. Both implementations remain internal development, not an independent
institutional assessment. Every native input/output and failure is retained.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

from contract_wire import H, ROOT
import work_oracle


SOURCE_PATHS = [
    'config/pon/ledger-v1.json',
    'config/pon/work-profile-v1.json',
    'config/pon/model-family-v1.json',
    'config/pon/continuity-v1.json',
    'formal/pon-nakamoto-v1/contract_wire.py',
    'formal/pon-nakamoto-v1/work_oracle.py',
    'formal/pon-nakamoto-v1/test_paired_work.py',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_periodic.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_prefix.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_one_zero.rs',
    'trillionnium/crates/trnm-crypto-primitives/examples/pon_paired_io.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/continuity_v1.rs',
    'trillionnium/crates/trnm-pon-node/tests/maintenance_paired_conformance.rs',
    'trillionnium/Cargo.lock',
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def maintenance():
    return ([((13 * i + 17) % 257) for i in range(work_oracle.CELLS)],
            [((29 * i + 31) % 263) for i in range(work_oracle.CELLS)])


class PairedWorkOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get('TRNM_PAIRED_WORK')
        if not binary:
            raise RuntimeError('TRNM_PAIRED_WORK must name the actual freshly built pon_paired_io')
        cls.binary = Path(binary).resolve()
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise RuntimeError('Build actual pon_paired_io first; absent binary is not a skipped pass')
        destination = os.environ.get('TRNM_PAIRED_WORK_OUTPUT')
        if not destination:
            raise RuntimeError('TRNM_PAIRED_WORK_OUTPUT must name a fresh retained evidence directory')
        cls.output = Path(destination).resolve()
        cls.output.mkdir(parents=True, exist_ok=False)
        cls.observations = []
        cls.before = cls.identity()
        (cls.output / 'identity-before.json').write_text(
            json.dumps(cls.before, indent=2, sort_keys=True) + '\n')

    @classmethod
    def identity(cls):
        return {
            'binary': str(cls.binary), 'binary_sha256': sha256(cls.binary),
            'python': sys.version, 'python_executable': sys.executable,
            'source_sha256': {name: sha256(ROOT / name) for name in SOURCE_PATHS},
            'binary_source_binding_requires_actual_build_receipt': True,
        }

    @classmethod
    def tearDownClass(cls):
        after = cls.identity()
        unchanged = after == cls.before
        (cls.output / 'identity-after.json').write_text(json.dumps(after, indent=2, sort_keys=True) + '\n')
        report = {
            'schema': 'pon-w1-paired-maintenance-python-native-v3',
            'result': 'PASS' if unchanged and len(cls.observations) == 70
                      and all(row['result'] == 'PASS' for row in cls.observations) else 'FAIL',
            'source_and_binary_unchanged': unchanged,
            'source_before': cls.before, 'source_after': after,
            'observations': cls.observations,
            'native_invocations': len(cls.observations),
            'full_proof_byte_comparisons': sum(row['expected_exit_code'] == 0 for row in cls.observations),
            'explicit_rejections': sum(row['expected_exit_code'] == 2 for row in cls.observations),
            'timings_are_process_and_io_observations_not_producer_cost': True,
            'work_hardness_accepted': False, 'public_network_accepted': False,
            'independent_institutional_review': False, 'production_activation': False,
        }
        (cls.output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'paired_work_output': str(cls.output), 'result': report['result'],
                          'native_invocations': len(cls.observations)}), flush=True)
        if not unchanged:
            raise AssertionError('native binary or compared source changed during the bridge checks')
        if report['result'] != 'PASS':
            raise AssertionError('complete paired bridge suite failed; retained report must remain FAIL')

    def case(self, name, data, *, source_class, expected=None, error=None, arguments=()):
        path = self.output / name
        path.mkdir()
        (path / 'input.bin').write_bytes(data)
        if expected is not None:
            (path / 'python-proof.bin').write_bytes(expected)
        command = [str(self.binary), *arguments]
        record = {
            'case': name, 'source_class': source_class, 'command': command,
            'expected_exit_code': 0 if expected is not None else 2,
            'input_sha256': hashlib.sha256(data).hexdigest(),
            'input_bytes': len(data), 'timed_out': False,
            'exit_code': None, 'result': 'FAIL', 'timeout_seconds': 30,
        }
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
        record['native_stdout_bytes'] = len(actual)
        record['native_stdout_sha256'] = hashlib.sha256(actual).hexdigest()
        record['native_stderr_sha256'] = hashlib.sha256(stderr).hexdigest()
        if expected is not None:
            record['python_proof_sha256'] = hashlib.sha256(expected).hexdigest()
        checks = {
            'completed': not record['timed_out'] and 'launch_error' not in record,
            'exit_code': record['exit_code'] == record['expected_exit_code'],
            'full_stdout': actual == (expected if expected is not None else b''),
            'stderr': stderr == (b'' if error is None else (error + '\n').encode()),
        }
        record['checks'] = checks
        record['result'] = 'PASS' if all(checks.values()) else 'FAIL'
        (path / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        self.observations.append(record)
        self.assertEqual(record['result'], 'PASS', f'{name}: inspect retained {path}')

    def compare_material(self, name, a, b, source_class, *, arguments=()):
        task = work_oracle.task_id(a, b)
        challenges = [bytes(32), bytes([7]) * 32, bytes([255]) * 32,
                      H('paired-bridge-challenge-v1', task)]
        for index, challenge in enumerate(challenges):
            with self.subTest(material=name, challenge=index):
                expected = work_oracle.prove(challenge, a, b)
                self.assertEqual(len(expected), 49188)
                data = challenge + work_oracle.field_bytes(a) + work_oracle.field_bytes(b)
                self.case(f'{name}-{index}', data, source_class=source_class, expected=expected,
                          arguments=arguments)

    def test_fixed_genesis_maintenance_full_bytes_match_the_scalar_relation(self):
        a, b = maintenance()
        self.assertEqual(work_oracle.task_id(a, b).hex(),
                         'c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496')
        self.compare_material('genesis-maintenance', a, b,
                              'genesis-policy-material-native-parent-admission-tested-separately')
        self.compare_material('genesis-maintenance-periodic', a, b,
                              'genesis-policy-material-native-parent-admission-tested-separately',
                              arguments=('maintenance-periodic',))
        for selector in ['maintenance-integer-paired', 'maintenance-prefix']:
            self.compare_material('genesis-' + selector, a, b,
                                  'genesis-policy-material-native-parent-admission-tested-separately',
                                  arguments=(selector,))

    def test_field_controls_cover_wraparound_dense_and_zero_without_admission_claims(self):
        q, cells = work_oracle.Q, work_oracle.CELLS
        self.compare_material('near-q', [q - 1] * cells,
                              [q - 1 - (i % 257) for i in range(cells)],
                              'canonical-arithmetic-control-only')
        dense = lambda label: [int.from_bytes(hashlib.sha256(
            label + i.to_bytes(4, 'little')).digest()[:4], 'little') % q for i in range(cells)]
        self.compare_material('hash-dense', dense(b'A'), dense(b'B'),
                              'canonical-arithmetic-control-no-rank-or-provenance-claim')
        self.compare_material('left-zero', [0] * cells, [i % 263 for i in range(cells)],
                              'canonical-arithmetic-control-only')

    def test_bounded_bridge_rejects_lengths_fields_and_extra_arguments(self):
        a, b = maintenance()
        data = bytes(32) + work_oracle.field_bytes(a) + work_oracle.field_bytes(b)
        for name, value in [('empty', b''), ('short', data[:-1]), ('extra-byte', data + b'\0')]:
            with self.subTest(case=name):
                self.case(name, value, source_class='malformed-bridge-input', error='LENGTH')
        for name, offset in [('first-field-q', 32), ('last-field-q', len(data) - 4)]:
            value = bytearray(data)
            value[offset:offset + 4] = work_oracle.Q.to_bytes(4, 'little')
            with self.subTest(case=name):
                self.case(name, bytes(value), source_class='noncanonical-bridge-input', error='WORK')
        self.case('extra-argument', data, arguments=('unexpected',),
                  source_class='unrecognized-bridge-operation', error='OPERATION')

    def test_periodic_selector_rejects_nonmaintenance_and_malformed_inputs(self):
        a, b = maintenance()
        challenge = bytes(32)
        exact = challenge + work_oracle.field_bytes(a) + work_oracle.field_bytes(b)
        for selector in ['maintenance-periodic', 'maintenance-integer-paired', 'maintenance-prefix']:
            arguments = (selector,)
            for name, operand, position in [('left-first', 0, 0), ('left-last', 0, 4095),
                                            ('right-first', 1, 0), ('right-last', 1, 4095)]:
                left, right = a[:], b[:]
                [left, right][operand][position] ^= 1
                data = challenge + work_oracle.field_bytes(left) + work_oracle.field_bytes(right)
                self.case(selector + '-unsupported-' + name, data, arguments=arguments,
                          source_class='canonical-nonmaintenance-control', error='UNSUPPORTED')
            for name, left, right in [('both-zero', [0] * 4096, [0] * 4096), ('swapped', b, a)]:
                data = challenge + work_oracle.field_bytes(left) + work_oracle.field_bytes(right)
                self.case(selector + '-unsupported-' + name, data, arguments=arguments,
                          source_class='canonical-nonmaintenance-control', error='UNSUPPORTED')
            for name, data in [('empty', b''), ('short', exact[:-1]), ('extra-byte', exact + b'\0')]:
                self.case(selector + '-' + name, data, arguments=arguments,
                          source_class='malformed-bridge-input', error='LENGTH')
            for name, offset in [('first-field-q', 32), ('last-field-q', len(exact) - 4)]:
                value = bytearray(exact)
                value[offset:offset + 4] = work_oracle.Q.to_bytes(4, 'little')
                self.case(selector + '-' + name, bytes(value), arguments=arguments,
                          source_class='noncanonical-bridge-input', error='WORK')
            self.case(selector + '-extra-argument', exact, arguments=(*arguments, 'extra'),
                      source_class='unrecognized-bridge-operation', error='OPERATION')


if __name__ == '__main__':
    unittest.main(verbosity=2)
