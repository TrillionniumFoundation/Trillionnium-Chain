"""Regression checks for concrete counterexamples and their scope."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hash_role_audit as audit


class HashRoleAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = audit.checked_sources()
        cls.permutation = audit.Poseidon2(cls.sources)
        cls.report = audit.check_vectors(cls.permutation)

    def test_official_known_answer_and_inverse(self):
        expected = [int(x, 16) for x in (
            '020cf04a1b214d14', '84e14aaaeacaed25', '1ae0f640e81c7457', 'a4d204cbaeb0d8a5',
            '0cf637b627b3a7ff', '788d304d948b486b', '7327133ea1949af4', 'f415abb924da395b')]
        self.assertEqual(self.permutation.permute(list(range(8))), expected)
        self.assertEqual(self.permutation.invert(expected), list(range(8)))

    def test_matrix_inverse_certificates_on_basis(self):
        for matrix, inverse in (
            (self.permutation.external_matrix, self.permutation.external_inverse),
            (self.permutation.internal_matrix, self.permutation.internal_inverse),
        ):
            for i in range(8):
                basis = [int(i == j) for j in range(8)]
                self.assertEqual(audit.mat_vec(matrix, audit.mat_vec(inverse, basis)), basis)
                self.assertEqual(audit.mat_vec(inverse, audit.mat_vec(matrix, basis)), basis)

    def test_arbitrary_compressor_collision_for_chosen_digests(self):
        for digest in ([0]*4, [0, 1, 2, 3], [audit.P-1]*4, [11, 22, 33, 44]):
            a = self.permutation.invert(digest + [0]*4)
            b = self.permutation.invert(digest + [0, 0, 0, 1])
            self.assertNotEqual(a, b)
            self.assertEqual(audit.compress(self.permutation, a[:4], a[4:]), digest)
            self.assertEqual(audit.compress(self.permutation, b[:4], b[4:]), digest)

    def test_collision_certificate_rejects_coordinate_mutations(self):
        collision = self.report['collision']
        for key in ('preimage_a', 'preimage_b'):
            for i in range(8):
                altered = collision[key][:]
                altered[i] = (altered[i] + 1) % audit.P
                self.assertNotEqual(audit.compress(self.permutation, altered[:4], altered[4:]), collision['common_compression_digest'])

    def test_four_field_leaf_is_zero_right_compression(self):
        for row in ([0]*4, [11, 22, 33, 44], [audit.P-1]*4):
            leaf, states = audit.hash_leaf(self.permutation, row)
            self.assertEqual(states, [row + [0]*4])
            self.assertEqual(leaf, audit.compress(self.permutation, row, [0]*4))

    def test_fixed_two_and_four_field_roles_overlap(self):
        for row in ([0, 0], [11, 22], [audit.P-1, audit.P-2]):
            self.assertEqual(audit.hash_leaf(self.permutation, row), audit.hash_leaf(self.permutation, row + [0, 0]))

    def test_each_fixed_leaf_final_state_is_in_compressor_domain(self):
        rows = self.report['fixed_width_last_call_relations']
        self.assertEqual([(x['base_field_width'], x['permutation_calls_per_leaf']) for x in rows],
                         [(2, 1), (4, 1), (18, 5), (27, 7), (516, 129), (7728, 1932)])
        self.assertTrue(all(x['leaf_equals_compression_of_last_state'] for x in rows))

    def test_invalid_field_or_shape_is_rejected(self):
        for state in ([0]*7, [0]*9, [audit.P]+[0]*7, [-1]+[0]*7, [True]+[0]*7):
            with self.assertRaises(ValueError):
                self.permutation.permute(state)
            with self.assertRaises(ValueError):
                self.permutation.invert(state)
        with self.assertRaises(ValueError):
            audit.compress(self.permutation, [0]*3, [0]*5)

    def test_primary_source_mutation_is_rejected(self):
        manifest = json.loads((audit.SOURCE/'manifest.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for record in manifest['files']:
                (root/record['file']).write_bytes((audit.SOURCE/record['file']).read_bytes())
            (root/'manifest.json').write_text(json.dumps(manifest))
            (root/manifest['files'][0]['file']).write_text('tampered')
            with patch.object(audit, 'SOURCE', root):
                with self.assertRaisesRegex(ValueError, 'source digest mismatch'):
                    audit.checked_sources()

    def test_no_security_certificate_or_fake_attack(self):
        claims = self.report['claims']
        for name in ('merkle_binding_attack_demonstrated', 'false_w1_proof_constructed',
                     'complete_noninteractive_bound_established', 'qrom_or_pq128_established'):
            self.assertIs(claims[name], False)
        self.assertEqual(self.report['qualification'], 'HOLD_NO_GO')
        self.assertIsNone(self.report['lifecycle_budget_effect']['numeric_lifetime_soundness_bound'])
        self.assertEqual(int(self.report['independent_ro_equality_probability']['denominator']), audit.P**4)


if __name__ == '__main__':
    unittest.main()
