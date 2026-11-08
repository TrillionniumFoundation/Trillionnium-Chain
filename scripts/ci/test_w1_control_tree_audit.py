#!/usr/bin/env python3
"""Known-answer and tamper controls for the fixed catalog/tree; no prover/network."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_control_tree_audit as audit

BUNDLE = Path(__file__).resolve().parents[2] / 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz'


class ControlTreeAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = audit.load_source_bundle(BUNDLE)
        cls.hasher = audit.Poseidon2.from_source(cls.sources[audit.CONST_PATH])
        cls.allowed = audit.parse_controls(cls.sources[audit.CONTROL_PATH])
        cls.catalog = audit.parse_catalog(cls.sources[audit.CONTROL_PATH])
        cls.result = audit.audit_sources(cls.sources)

    def test_permutation_matches_upstream_known_answer(self):
        # Published in fixed upstream poseidon2/mod.rs, not computed by this test.
        goal = (
            0x2ed3e23d, 0x12921fb0, 0x0e659e79, 0x61d81dc9, 0x32bae33b, 0x62486ae3,
            0x1e681b60, 0x24b91325, 0x2a2ef5b9, 0x50e8593e, 0x5bc818ec, 0x10691997,
            0x35a14520, 0x2ba6a3c5, 0x279d47ec, 0x55014e81, 0x5953a67f, 0x2f403111,
            0x6b8828ff, 0x1801301f, 0x2749207a, 0x3dc9cf21, 0x3c985ba2, 0x57a99864,
        )
        self.assertEqual(self.hasher.permute(tuple(range(24))), goal)

    def test_aligned_sponge_matches_upstream_interpreter_golden(self):
        values = (
            943718400, 1887436800, 2013125296, 1761607679, 692060158, 1761607634,
            566231037, 1509949437, 440401916, 1384120316, 314572795, 1258291195,
            188743674, 1132462074, 62914553, 1006632953, 1950351353, 880803832,
            1824522232, 754974711, 1698693111, 629145590, 1572863990, 503316469,
            1447034869, 377487348, 1321205748, 251658227, 1195376627, 125829106,
            1069547506, 2013265906,
        )
        goal = (0x722baada, 0x5b352fed, 0x3684017b, 0x540d4a7b,
                0x44ffd422, 0x48615f97, 0x1a496f45, 0x203ca999)
        self.assertEqual(self.hasher.hash_elements(values), goal)

    def test_unaligned_sponge_matches_upstream_interpreter_golden(self):
        values = (
            943718400, 1887436800, 2013125296, 1761607679, 692060158, 1635778558,
            566231037, 1509949437, 440401916, 1384120316, 314572795, 1258291195,
            188743674, 1132462074, 62914553, 1006632953, 1950351353,
        )
        goal = (0x622615d7, 0x1cfe9764, 0x166cb1c9, 0x76febcde,
                0x6056219f, 0x326359cf, 0x5c2cca75, 0x233dc3ff)
        self.assertEqual(self.hasher.hash_elements(values), goal)

    def test_catalog_tree_matches_fixed_sdk_root(self):
        self.assertEqual(self.result['root'], audit.EXPECTED_ROOT)
        self.assertEqual(self.result['allowed_program_count'], 27)
        self.assertEqual(self.result['sdk_catalog_count'], 32)
        self.assertEqual(self.result['level_widths'], [256, 128, 64, 32, 16, 8, 4, 2, 1])
        self.assertEqual(self.result['zero_padding_leaves'], 229)
        self.assertEqual(self.result['final_join']['index'], 1)
        self.assertTrue(all(r['inclusion_recomputed'] for r in self.result['allowed_programs']))

    def test_catalog_recomputation_does_not_certify_semantics_or_qrom(self):
        for field in ('complete_cargo_graph_audited', 'zkr_binaries_rebuilt',
                      'control_ids_derived_from_zkr_binaries', 'program_semantics_audited',
                      'complete_qrom_bound_established'):
            self.assertIs(self.result[field], False)
        self.assertTrue(all(not row['program_semantics_audited']
                            for row in self.result['allowed_programs']))

    def test_sdk_catalog_is_not_the_default_allowlist(self):
        outside = {r['program'] for r in self.result['sdk_programs_outside_default_root']}
        self.assertEqual(outside, {'lift_rv32im_v2_23.zkr', 'lift_rv32im_v2_24.zkr',
                                  'lift_rv32im_v2_povw_23.zkr', 'lift_rv32im_v2_povw_24.zkr',
                                  'test_recursion_circuit.zkr'})
        ids = [r['control_id'] for r in self.catalog]
        self.assertNotEqual(audit.build_tree(ids, self.hasher)[-1][0], audit.EXPECTED_ROOT)
        with self.assertRaisesRegex(audit.ControlTreeError, 'roster/order'):
            audit.validate_catalog(self.catalog, self.catalog)

    def test_program_reordering_is_refused_and_changes_root(self):
        changed = copy.deepcopy(self.allowed)
        changed[0], changed[1] = changed[1], changed[0]
        with self.assertRaisesRegex(audit.ControlTreeError, 'roster/order'):
            audit.validate_catalog(changed, self.catalog)
        self.assertNotEqual(audit.build_tree([r['control_id'] for r in changed], self.hasher)[-1][0],
                            audit.EXPECTED_ROOT)

    def test_missing_and_added_program_are_refused(self):
        for changed in (self.allowed[:-1], self.allowed + [self.catalog[-1]]):
            with self.subTest(count=len(changed)):
                with self.assertRaisesRegex(audit.ControlTreeError, 'roster/order'):
                    audit.validate_catalog(changed, self.catalog)

    def test_unknown_same_size_program_roster_is_refused(self):
        changed = copy.deepcopy(self.allowed)
        changed[-1]['program'] = 'z_unknown.zkr'
        with self.assertRaisesRegex(audit.ControlTreeError, 'roster/order'):
            audit.validate_catalog(changed, self.catalog)

    def test_duplicate_control_id_is_refused(self):
        changed = copy.deepcopy(self.allowed)
        changed[-1]['control_id'] = changed[0]['control_id']
        with self.assertRaisesRegex(audit.ControlTreeError, 'duplicate control ID'):
            audit.validate_catalog(changed, self.catalog)

    def test_named_catalog_disagreement_is_refused(self):
        changed = copy.deepcopy(self.allowed)
        changed[-1]['control_id'] = '00' * 32
        with self.assertRaisesRegex(audit.ControlTreeError, 'differs from named catalog'):
            audit.validate_catalog(changed, self.catalog)

    def test_altered_final_join_is_refused_even_in_matching_catalogs(self):
        allowed, catalog = copy.deepcopy(self.allowed), copy.deepcopy(self.catalog)
        for records in (allowed, catalog):
            next(r for r in records if r['program'] == 'join.zkr')['control_id'] = '00' * 32
        with self.assertRaisesRegex(audit.ControlTreeError, 'final join control ID drift'):
            audit.validate_catalog(allowed, catalog)

    def test_only_join_is_a_different_control_root(self):
        result = audit.build_tree([audit.EXPECTED_JOIN], self.hasher)
        self.assertNotEqual(result[-1][0], audit.EXPECTED_ROOT)

    def test_inclusion_path_reproduces_tree_root(self):
        join = self.result['final_join']
        self.assertEqual(audit.inclusion_root(join['control_id'], join['index'], join['merkle_path'],
                                             self.sources), audit.EXPECTED_ROOT)

    def test_wrong_index_or_path_reproduces_a_different_root(self):
        join = self.result['final_join']
        path = list(join['merkle_path'])
        path[0] = '00' * 32
        cases = ((0, join['merkle_path']), (1, path), (1, list(reversed(join['merkle_path']))))
        for index, siblings in cases:
            with self.subTest(index=index, first=siblings[0]):
                self.assertNotEqual(audit._inclusion_root(join['control_id'], index, siblings, self.hasher),
                                    audit.EXPECTED_ROOT)

    def test_short_and_long_paths_are_refused(self):
        join = self.result['final_join']
        for siblings in (join['merkle_path'][:-1], join['merkle_path'] + ['00' * 32]):
            with self.assertRaisesRegex(audit.ControlTreeError, 'exactly 8 siblings'):
                audit._inclusion_root(join['control_id'], 1, siblings, self.hasher)

    def test_out_of_range_and_boolean_path_indices_are_refused(self):
        join = self.result['final_join']
        for index in (-1, 256, 2**32 - 1, True):
            with self.subTest(index=index):
                with self.assertRaisesRegex(audit.ControlTreeError, 'index outside'):
                    audit._inclusion_root(join['control_id'], index, join['merkle_path'], self.hasher)

    def test_noncanonical_leaf_and_sibling_are_refused_before_hashing(self):
        join = self.result['final_join']
        for value in (audit.P, 0xffffffff):
            malformed = struct.pack('<8I', value, *([0] * 7)).hex()
            for is_leaf in (False, True):
                leaf, siblings = join['control_id'], list(join['merkle_path'])
                if is_leaf:
                    leaf = malformed
                else:
                    siblings[-1] = malformed
                with self.subTest(value=value, leaf=is_leaf):
                    with mock.patch.object(self.hasher, 'hash_pair', side_effect=AssertionError('must not hash')):
                        with self.assertRaisesRegex(audit.ControlTreeError, 'noncanonical'):
                            audit._inclusion_root(leaf, 1, siblings, self.hasher)

    def test_canonical_field_boundary_is_preserved(self):
        words = (0, audit.P - 1, 1, 2, 3, 4, 5, 6)
        digest = struct.pack('<8I', *words).hex()
        self.assertEqual(audit._digest_words(digest), words)
        self.assertEqual(len(self.hasher.hash_pair(digest, '00' * 32)), 64)

    def test_montgomery_decoding_is_not_ordinary_integer_encoding(self):
        left, right = (r['control_id'] for r in self.allowed[:2])
        raw = struct.unpack('<16I', bytes.fromhex(left + right))
        wrong = struct.pack('<8I', *(v * audit.MONTGOMERY_R % audit.P
                                    for v in self.hasher.hash_elements(raw))).hex()
        self.assertNotEqual(self.hasher.hash_pair(left, right), wrong)

    def test_length_extension_caveat_is_visible_in_unpadded_hash(self):
        # These *are* equal. This audit must not claim general variable-length hashing security.
        self.assertEqual(self.hasher.hash_elements([1]), self.hasher.hash_elements([1, 0]))

    def test_tree_rejects_256_leaves_like_sdk_constructor(self):
        with self.assertRaisesRegex(audit.ControlTreeError, '1..255 leaves'):
            audit.build_tree(['00' * 32] * 256, self.hasher)

    def test_source_mutation_and_missing_source_fail_closed(self):
        for name in audit.SOURCE_SHA256:
            with self.subTest(source=name):
                changed = dict(self.sources)
                changed[name] += '\n'
                with self.assertRaisesRegex(audit.ControlTreeError, 'SHA-256 mismatch'):
                    audit.audit_sources(changed)
                del changed[name]
                with self.assertRaisesRegex(audit.ControlTreeError, 'missing source'):
                    audit.audit_sources(changed)

    def test_partial_control_parser_does_not_ignore_malformed_entry(self):
        source = self.sources[audit.CONTROL_PATH].replace(
            'digest!("' + self.allowed[0]['control_id'] + '"), // recursion identity.zkr',
            'digest!("not-a-digest"), // recursion identity.zkr', 1)
        with self.assertRaisesRegex(audit.ControlTreeError, 'unsupported entry'):
            audit.parse_controls(source)

    def test_constants_parser_rejects_expressions_and_noncanonical_values(self):
        source = self.sources[audit.CONST_PATH]
        first = audit._one(r'ROUND_CONSTANTS:.*?baby_bear_array!\[\s*(0x[0-9a-fA-F]+)',
                           source, 'first constant').group(1)
        for replacement in ('0x0 + 1', str(audit.P)):
            with self.subTest(replacement=replacement):
                with self.assertRaises(audit.ControlTreeError):
                    audit.Poseidon2.from_source(source.replace(first, replacement, 1))

    def test_bundle_duplicate_source_record_is_refused(self):
        payload = json.loads(gzip.decompress(BUNDLE.read_bytes()))
        payload['files'].append(copy.deepcopy(payload['files'][0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'duplicated.json.gz'
            path.write_bytes(gzip.compress(json.dumps(payload).encode()))
            with self.assertRaisesRegex(audit.ControlTreeError, 'duplicate source bundle'):
                audit.load_source_bundle(path)

    def test_bundle_relabelled_mutation_cannot_repin_source(self):
        payload = json.loads(gzip.decompress(BUNDLE.read_bytes()))
        record = next(r for r in payload['files'] if r['path'] == audit.CONST_PATH)
        record['content'] += '\n'
        raw = record['content'].encode()
        record['bytes'] = len(raw)
        record['sha256'] = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'repinned.json.gz'
            path.write_bytes(gzip.compress(json.dumps(payload).encode()))
            with self.assertRaisesRegex(audit.ControlTreeError, 'fixed source SHA-256 mismatch'):
                audit.load_source_bundle(path)

    def test_cli_never_overwrites_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.json'
            path.write_text('earlier observation\n')
            with mock.patch.object(sys, 'argv', ['audit', '--source-bundle', str(BUNDLE), '--out', str(path)]):
                with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    self.assertEqual(audit.main(), 1)
            self.assertEqual(path.read_text(), 'earlier observation\n')


if __name__ == '__main__':
    unittest.main()
