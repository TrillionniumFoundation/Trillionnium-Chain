#!/usr/bin/env python3
"""Native arithmetic KATs, malformed inputs, and strict result boundaries.

This suite builds the independent C kernel and exercises a small zero-code
commitment. It does not claim to rerun all 27 large program commitments.
"""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('w1_zkr_control_id_audit',
                                            ROOT / 'scripts/w1_zkr_control_id_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class W1ZkrControlIdAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (cls.shape, cls.helper, cls.engine, cls.catalog, cls.allowed,
         source, header, cls.provenance) = AUDIT.load_context(ROOT)
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        (cls.directory / 'w1_zkr_control_id.c').write_bytes(source)
        (cls.directory / 'w1_zkr_constants.h').write_bytes(header)
        compiler = shutil.which('cc')
        if compiler is None:
            raise RuntimeError('C compiler required for the native audit tests; no skip fallback')
        cls.binary = cls.directory / 'control-id'
        result = subprocess.run([compiler, '-O3', '-std=c11', '-fopenmp', '-Wall', '-Wextra', '-Werror',
                                 str(cls.directory / 'w1_zkr_control_id.c'), '-o', str(cls.binary)],
                                capture_output=True, timeout=60, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode('utf-8', errors='replace'))

    def fixture_result(self) -> dict:
        expected = self.catalog['join.zkr']
        raw = struct.unpack('<8I', bytes.fromhex(expected))
        normal = [value * self.helper.MONTGOMERY_R_INV % AUDIT.P for value in raw]
        return {'control_id': expected, 'code_rows': 259612, 'trace_po2': 18,
                'domain_rows': 1 << 20, 'threads': 4, 'root_normal_words': normal,
                'lde_samples_normal': [0] * 16,
                'phase_seconds': {'lde': 0.1, 'leaves': 0.2, 'tree': 0.1}}

    def test_native_seven_independent_known_answers_pass(self) -> None:
        result = subprocess.run([str(self.binary), '--self-test'], capture_output=True,
                                timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),
                         {'self_test': 'PASS', 'checks': 7, 'arithmetic': 'normal BabyBear'})

    def test_native_zero_code_commitment_matches_analytic_constant_tree(self) -> None:
        program = self.directory / 'zero.zkr'
        program.write_bytes(bytes(23 * 4))
        result = subprocess.run([str(self.binary), str(program), '11', '1'], capture_output=True,
                                timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        actual = json.loads(result.stdout)
        digest = self.engine.hash_elements([0] * 23)
        # 2^11 code rows become 2^13 LDE rows; every leaf has the same value.
        for _ in range(13):
            digest = self.engine.permute((*digest, *digest, *([0] * 8)))[:8]
        expected = struct.pack('<8I', *(value * self.helper.MONTGOMERY_R % AUDIT.P for value in digest)).hex()
        self.assertEqual(actual['control_id'], expected)
        self.assertEqual(actual['root_normal_words'], list(digest))
        self.assertNotEqual(expected, '00' * 32)
        self.assertEqual(actual['code_rows'], 1)
        # This checks a commitment encoding; it does not make zero code a valid
        # executable program or prove that no other code can have digest zero.

    def test_native_rejects_partial_rows_noncanonical_words_and_bad_limits(self) -> None:
        program = self.directory / 'invalid.zkr'
        cases = [(b'', '11', '1'), (b'\0' * 4, '11', '1'),
                 (struct.pack('<I', AUDIT.P) + bytes(88), '11', '1'),
                 (bytes(92), '10', '1'), (bytes(92), '19', '1'),
                 (bytes(92), '11', '5'), (bytes(92), '11x', '1')]
        for payload, po2, threads in cases:
            program.write_bytes(payload)
            result = subprocess.run([str(self.binary), str(program), po2, threads],
                                    capture_output=True, timeout=20, check=False)
            with self.subTest(po2=po2, threads=threads, bytes=len(payload)):
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')

    def test_native_result_requires_root_bytes_normal_words_and_exact_geometry(self) -> None:
        baseline = self.fixture_result()
        AUDIT.validate_native_result(baseline, 259612, self.catalog['join.zkr'], 4)
        mutations = [('control_id', '00' * 32), ('code_rows', 259613),
                     ('trace_po2', 17), ('domain_rows', 1 << 19), ('threads', 3),
                     ('root_normal_words', [0] * 8), ('lde_samples_normal', [0] * 15)]
        for key, value in mutations:
            changed = copy.deepcopy(baseline)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(AUDIT.ControlIdAuditError):
                AUDIT.validate_native_result(changed, 259612, self.catalog['join.zkr'], 4)
        recorded = json.loads((ROOT / self.shape.EVIDENCE / 'control-ids-all27.json').read_text())
        shapes = json.loads((ROOT / self.shape.EVIDENCE / 'zkr-programs.json').read_text())
        by_name = {row['program']: row for row in shapes['programs']}
        self.assertEqual(recorded['source_provenance'], self.provenance)
        self.assertEqual(recorded['requested_programs'], sorted(self.allowed))
        self.assertEqual(recorded['completed_programs'], 27)
        self.assertEqual([row['program'] for row in recorded['programs']], sorted(self.allowed))
        computed = []
        for row in recorded['programs']:
            expected = by_name[row['program']]
            self.assertEqual(row['bytecode_sha256'], expected['sha256'])
            self.assertEqual(row['geometry']['code_rows'], expected['code_rows'])
            run = row['native_run']
            self.assertEqual(run['exit_code'], 0)
            self.assertIs(run['timed_out'], False)
            self.assertEqual(AUDIT.sha256(run['stdout'].encode()), run['stdout_sha256'])
            self.assertEqual(run['stderr'], '')
            result = json.loads(run['stdout'])
            AUDIT.validate_native_result(result, expected['code_rows'], self.catalog[row['program']], 4)
            self.assertEqual(row['computed_control_id'], result['control_id'])
            self.assertIs(row['matches_fixed_catalog'], True)
            computed.append(row['computed_control_id'])
        root = self.helper.build_tree(computed, self.engine)[-1][0]
        self.assertEqual(root, recorded['control_root_from_computed_ids'])
        self.assertEqual(root, self.helper.EXPECTED_ROOT)
        self.assertEqual({key for key, value in recorded['qualification'].items() if value is True}, {
            'requested_bytecode_to_fri_control_ids_recomputed',
            'all_27_default_named_control_ids_recomputed',
            'default_control_root_recomputed_from_bytecode',
        })
        self.assertIs(recorded['qualification']['intended_recursive_program_semantics_proved'], False)
        self.assertIs(recorded['qualification']['valid_code_zero_control_digest_excluded'], False)

    def test_native_result_rejects_boolean_numeric_aliases_and_nonfinite_observations(self) -> None:
        baseline = self.fixture_result()
        variants = []
        for key in ('code_rows', 'trace_po2', 'domain_rows', 'threads'):
            changed = copy.deepcopy(baseline)
            changed[key] = False
            variants.append(changed)
        for value in (False, AUDIT.P, -1):
            changed = copy.deepcopy(baseline)
            changed['root_normal_words'][0] = value
            variants.append(changed)
        for value in (False, float('nan'), float('inf'), -1):
            changed = copy.deepcopy(baseline)
            changed['phase_seconds']['lde'] = value
            variants.append(changed)
        for changed in variants:
            with self.assertRaises(AUDIT.ControlIdAuditError):
                AUDIT.validate_native_result(changed, 259612, self.catalog['join.zkr'], 4)

    def test_native_result_rejects_missing_extra_and_null_payloads(self) -> None:
        baseline = self.fixture_result()
        missing = copy.deepcopy(baseline)
        del missing['control_id']
        extra = copy.deepcopy(baseline)
        extra['unreviewed_success'] = True
        for changed in (missing, extra):
            with self.assertRaises(AUDIT.ControlIdAuditError):
                AUDIT.validate_native_result(changed, 259612, self.catalog['join.zkr'], 4)
        with self.assertRaises((AUDIT.ControlIdAuditError, TypeError)):
            AUDIT.validate_native_result(None, 259612, self.catalog['join.zkr'], 4)

    def test_degree_order_roots_match_small_reference_dft_and_inverse(self) -> None:
        sources = self.provenance['reference_known_answers']
        self.assertEqual(sources['KAT_NTT8'][0], 36)
        self.assertNotEqual(sources['KAT_NTT8'][1], sources['KAT_NTT8'][-1])
        values = list(range(1, 9))
        reverse_root = pow(1801542727, -1, AUDIT.P)
        self.assertEqual(AUDIT.naive_dft(values, reverse_root, True), sources['KAT_IFFT8'])
        self.assertEqual(AUDIT.naive_dft(sources['KAT_IFFT8'], 1801542727), values)

    def test_source_integrity_and_requested_roster_fail_before_native_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'helper.py'
            source.write_text('raise SystemExit(0)\n')
            with self.assertRaisesRegex(AUDIT.ControlIdAuditError, 'SHA-256 mismatch'):
                AUDIT.checked_module(source, AUDIT.SHAPE_SHA256, '_bad_helper')
            for requested in (['join.zkr', 'join.zkr'], ['test_recursion_circuit.zkr'],
                              ['lift_rv32im_v2_23.zkr'], []):
                with self.subTest(requested=requested), self.assertRaisesRegex(AUDIT.ControlIdAuditError, 'roster'):
                    AUDIT.audit(ROOT, Path(directory) / 'absent.zip', Path(directory) / 'never-created',
                                requested)
            self.assertFalse((Path(directory) / 'never-created').exists())


if __name__ == '__main__':
    unittest.main()
