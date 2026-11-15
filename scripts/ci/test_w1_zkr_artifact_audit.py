#!/usr/bin/env python3
"""Adverse ZKR encodings and checks on the recorded full-artifact observation.

These local regressions do not redownload or rehash the 57 MiB remote ZIP.
The standalone audit does that when explicitly supplied with --zkr.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('w1_zkr_artifact_audit',
                                            ROOT / 'scripts/w1_zkr_artifact_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class W1ZkrArtifactAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog, cls.allowed, cls.provenance = AUDIT.load_context(ROOT)
        cls.recorded = json.loads((ROOT / AUDIT.EVIDENCE / 'zkr-programs.json').read_text())

    def test_recorded_actual_zip_inventory_has_all_32_and_default_27(self) -> None:
        report = self.recorded
        self.assertEqual(report['zip']['sha256'], AUDIT.ZIP_SHA256)
        self.assertEqual(report['zip']['bytes'], 59768781)
        self.assertEqual(report['program_count'], 32)
        self.assertEqual(report['default_named_program_count'], 27)
        self.assertEqual([row['program'] for row in report['programs']], sorted(self.catalog))
        self.assertEqual({row['program'] for row in report['programs'] if row['in_default_named_allowlist']},
                         self.allowed)
        for row in report['programs']:
            self.assertEqual(row['declared_poseidon2_control_id'], self.catalog[row['program']])
            self.assertRegex(row['sha256'], r'^[0-9a-f]{64}$')
            self.assertEqual(row['bytes'], row['code_rows'] * 23 * 4)
            self.assertEqual(row['unused_code_rows_at_evaluated_capacity'], 261120 - row['code_rows'])

    def test_recorded_join_povw_has_only_eight_capacity_rows_remaining(self) -> None:
        row = next(row for row in self.recorded['programs'] if row['program'] == 'join_povw.zkr')
        self.assertEqual(row['bytes'], 24022304)
        self.assertEqual(row['code_rows'], 261112)
        self.assertEqual(row['unused_code_rows_at_evaluated_capacity'], 8)
        self.assertEqual(row['minimum_po2_from_capacity_inequality_only'], 18)

    def test_shape_uses_little_endian_canonical_words_and_exact_width(self) -> None:
        data = struct.pack('<23I', *([AUDIT.P - 1] + list(range(22))))
        result = AUDIT.program_shape(data)
        self.assertEqual(result['u32_words'], 23)
        self.assertEqual(result['code_rows'], 1)
        self.assertEqual(result['maximum_word'], AUDIT.P - 1)
        self.assertEqual(result['noncanonical_word_count'], 0)

    def test_partial_words_and_partial_rows_are_rejected(self) -> None:
        for data in (b'', b'\0' * 3, b'\0' * 4, b'\0' * 88, b'\0' * 96):
            with self.subTest(length=len(data)), self.assertRaises(AUDIT.ZkrAuditError):
                AUDIT.program_shape(data)

    def test_over_capacity_and_wrong_exponents_are_rejected(self) -> None:
        data = bytes(23 * 4)
        for po2 in (True, 10, 25, -1, '18'):
            with self.subTest(po2=po2), self.assertRaises(AUDIT.ZkrAuditError):
                AUDIT.program_shape(data, po2)
        over_capacity = bytes(((1 << 18) - 1024 + 1) * 23 * 4)
        with self.assertRaisesRegex(AUDIT.ZkrAuditError, 'exceeds'):
            AUDIT.program_shape(over_capacity)

    def test_noncanonical_field_words_fail_the_lossless_encoding_claim(self) -> None:
        for word in (AUDIT.P, 0xffffffff):
            data = struct.pack('<I', word) + bytes(22 * 4)
            with self.subTest(word=word), self.assertRaisesRegex(AUDIT.ZkrAuditError, 'canonical'):
                AUDIT.program_shape(data)

    def test_missing_duplicate_extra_and_path_shaped_zip_entries_rejected(self) -> None:
        good = sorted(self.catalog)
        AUDIT.validate_inventory(good, set(self.catalog))
        for names in (good[:-1], good + [good[0]], good + ['unknown.zkr'],
                      ['../' + good[0], *good[1:]]):
            with self.subTest(names=names), self.assertRaises(AUDIT.ZkrAuditError):
                AUDIT.validate_inventory(names, set(self.catalog))

    def test_artifact_digest_pin_rejects_unrelated_content_before_zip_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'zkr.zip'
            path.write_bytes(b'PK\x03\x04' + b'wrong artifact')
            with self.assertRaisesRegex(AUDIT.ZkrAuditError, 'SHA-256 mismatch'):
                AUDIT.read_pinned(path, AUDIT.ZIP_SHA256, 1024)

    def test_shape_and_record_do_not_claim_control_id_or_trace_semantics(self) -> None:
        zero_shape = AUDIT.program_shape(bytes(23 * 4))
        self.assertIs(zero_shape['all_code_words_zero'], True)
        self.assertIs(zero_shape['declared_control_id_recomputed_from_bytecode'], False)
        self.assertIs(zero_shape['bytecode_execution_or_reachable_trace_verified'], False)
        qualifications = self.recorded['qualification']
        self.assertEqual({key for key, value in qualifications.items() if value is True}, {
            'complete_official_zip_digest_verified',
            'all_named_artifact_sha256_and_row_shapes_computed',
            'capacity_inequality_at_recorded_outer_po2_checked',
        })
        for key in ('bytecode_to_fri_control_id_recomputed', 'intended_program_semantics_proved',
                    'valid_code_zero_control_digest_excluded', 'all_reachable_traces_certified'):
            self.assertIs(qualifications[key], False)
        for row in self.recorded['programs']:
            self.assertIs(row['declared_control_id_recomputed_from_bytecode'], False)
            self.assertIs(row['bytecode_execution_or_reachable_trace_verified'], False)


if __name__ == '__main__':
    unittest.main()
