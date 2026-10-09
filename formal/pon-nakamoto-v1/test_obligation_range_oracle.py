"""Independent boundary controls for the complete monetary range relation.

These pure Python controls build authentic membership for deliberately incomplete
disclosures. They do not claim native M06 or W1 execution; actual signed native
observations are checked separately by the reader CLI.
"""
import copy
import json
import unittest

import account_archive_oracle as archive
import obligation_range_oracle as oracle


class MonetaryRangeOracle(unittest.TestCase):
    def setUp(self):
        self.anchor = dict(parent_checkpoint=[1] * 32, parent_id=[2] * 32,
                           parent_height=7, state_commitment=[3] * 32)
        self.partition = {
            'aaa': None, 'bbb': True, 'ccc': 1, 'ddd': 'payload',
            'quota9': 0, 'quota:a': dict(remaining=0, deadline=2),
            'quota:b': dict(remaining=30, deadline=900), 'quota;': 0,
            'release:a': dict(remaining=40, deadline=800), 'release;': 0,
            'reward:a': dict(amount=10, maturity=8),
            'reward:b': dict(amount=20, maturity=900), 'reward;': 0,
            'task:a': dict(remaining=10, deadline=8),
            'task:b': dict(remaining=20, deadline=901),
            'task:c': dict(remaining=0, deadline=2),
            'task:d': dict(remaining=30, deadline=902),
            'task;': 0, 'zzz:a': 0, 'zzz:b': 1, 'zzz:c': 2, 'zzz:d': 3,
        }
        self.reference = oracle.reference_partition(self.partition, self.anchor)
        self.proof = copy.deepcopy(self.reference['proof'])

    def check(self, proof=None):
        return oracle.check_partition(self.proof if proof is None else proof,
                                      self.partition, self.anchor)

    def disclosure(self, selected):
        """Construct authentic subset membership without completeness rules."""
        proof = copy.deepcopy(self.proof)
        all_rows = oracle.source_rows(self.partition)
        digests = self.reference['index']['digests']
        proof['rows'] = [row for row in all_rows if row['rank'] in selected]
        proof['frontier'] = []
        def walk(first, count):
            if not any(rank in selected for rank in range(first, first + count)):
                proof['frontier'].append(dict(first=first, count=count,
                                               digest=list(digests[first, count])))
            elif count > 1:
                left = count // 2
                walk(first, left)
                walk(first + left, count - left)
        walk(0, len(all_rows))
        self.assert_membership_root(proof)
        return proof

    def assert_membership_root(self, proof):
        leaves = {row['rank']: archive.digest(b'monetary-obligation-range-leaf-v1',
            row['rank'].to_bytes(4, 'little'), row['key'].encode('utf-8'),
            archive.canonical(row['value'])) for row in proof['rows']}
        frontier = {(row['first'], row['count']): bytes(row['digest']) for row in proof['frontier']}
        def fold(first, count):
            if (first, count) in frontier:
                return frontier[first, count]
            if count == 1:
                return leaves[first]
            left = count // 2
            return archive.digest(b'monetary-obligation-range-node-v1',
                first.to_bytes(4, 'little'), count.to_bytes(4, 'little'),
                fold(first, left), fold(first + left, count - left))
        self.assertEqual(fold(0, proof['non_account_count']), bytes(self.proof['index_root']))

    def test_full_sorted_source_includes_future_and_zero_amount_rows(self):
        result = self.check()
        self.assertEqual([row['prefix'] for row in result['ranges']], list(oracle.PREFIXES))
        self.assertEqual([row['matched_rows'] for row in result['ranges']], [2, 1, 2, 4])
        self.assertEqual(result['monetary'], {key: value for key, value in sorted(self.partition.items())
                                             if key.startswith(oracle.PREFIXES)})
        self.assertIn('task:c', result['monetary'])
        self.assertIn('task:d', result['monetary'])
        self.assertEqual(result['observation']['monetary_rows'], 9)
        self.assertEqual(result['observation']['index_leaf_hashes'], len(self.partition))
        self.assertEqual(result['observation']['index_branch_hashes'], len(self.partition)-1)
        self.assertFalse(result['observation']['consensus_admission'])
        self.assert_membership_root(self.proof)

    def test_empty_partition_and_single_edge_rows_are_canonical(self):
        for partition in ({}, {'aaa': 0}, {'quota:a': dict(remaining=0)}, {'zzz': 0}):
            with self.subTest(partition=partition):
                result = oracle.reference_partition(partition, self.anchor)
                oracle.check_partition(result['proof'], partition, self.anchor)
                self.assertEqual(len(result['proof']['rows']), len(partition))
                self.assertEqual(result['proof']['frontier'], [])
        empty = oracle.reference_partition({}, self.anchor)
        self.assertEqual(bytes(empty['proof']['index_root']),
                         archive.digest(b'monetary-obligation-range-empty-v1'))
        self.assertEqual(empty['observation']['index_branch_hashes'], 0)

    def test_empty_ranges_share_nearest_boundaries_once(self):
        partition = {'aaa': 0, 'release9': 0, 'task;': 0, 'zzz': 0}
        result = oracle.reference_partition(partition, self.anchor)
        oracle.check_partition(result['proof'], partition, self.anchor)
        self.assertTrue(all(row['matched_rows'] == 0 for row in result['ranges']))
        self.assertEqual([row['rank'] for row in result['proof']['rows']], [0, 1, 2])
        self.assertEqual(result['observation']['monetary_rows'], 0)
        for row in result['ranges']:
            self.assertEqual(row['predecessor_rank'] + 1, row['successor_rank'])

    def test_lexical_endpoints_unicode_keys_and_arbitrary_suffixes(self):
        partition = {'quota9': 0, 'quota:': 1, 'quota:\x00': 2, 'quota:汉': 3,
                     'quota;': 4, 'quota;more': 5, 'task:': 6, 'task;': 7, '汉': 8}
        result = oracle.reference_partition(partition, self.anchor)
        oracle.check_partition(result['proof'], partition, self.anchor)
        self.assertEqual(result['monetary'], {'quota:': 1, 'quota:\x00': 2, 'quota:汉': 3, 'task:': 6})
        self.assertEqual(result['ranges'][0]['matched_rows'], 3)

    def test_authentic_subset_cannot_omit_any_due_future_or_zero_obligation(self):
        selected = {row['rank'] for row in self.proof['rows']}
        for key in ('quota:a', 'release:a', 'reward:b', 'task:a', 'task:b', 'task:c', 'task:d'):
            rank = next(row['rank'] for row in self.proof['rows'] if row['key'] == key)
            incomplete = self.disclosure(selected - {rank})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'COMPLETE_ROWS$'):
                self.check(incomplete)

    def test_authentic_subset_cannot_omit_immediate_boundary(self):
        selected = {row['rank'] for row in self.proof['rows']}
        monetary = self.reference['monetary']
        boundaries = [row for row in self.proof['rows'] if row['key'] not in monetary]
        self.assertTrue(boundaries)
        for row in boundaries:
            incomplete = self.disclosure(selected - {row['rank']})
            with self.subTest(key=row['key']), self.assertRaisesRegex(ValueError, 'COMPLETE_ROWS$'):
                self.check(incomplete)

    def test_authentic_extra_non_boundary_leaf_is_noncanonical(self):
        selected = {row['rank'] for row in self.proof['rows']}
        extra = next(rank for rank in range(len(self.partition)) if rank not in selected)
        inflated = self.disclosure(selected | {extra})
        with self.assertRaisesRegex(ValueError, 'COMPLETE_ROWS$'):
            self.check(inflated)

    def test_split_hidden_subtree_is_valid_membership_but_noncanonical_frontier(self):
        proof = copy.deepcopy(self.proof)
        index, node = next((i, row) for i, row in enumerate(proof['frontier']) if row['count'] > 1)
        first, count = node['first'], node['count']
        left = count // 2
        children = [(first, left), (first + left, count - left)]
        proof['frontier'][index:index+1] = [dict(first=start, count=size,
            digest=list(self.reference['index']['digests'][start, size])) for start, size in children]
        self.assert_membership_root(proof)
        with self.assertRaisesRegex(ValueError, 'CANONICAL_FRONTIER$'):
            self.check(proof)

    def test_parent_and_count_roots_require_exact_external_anchor(self):
        for field in ('parent_checkpoint', 'parent_id', 'state_commitment', 'index_root'):
            proof = copy.deepcopy(self.proof)
            proof[field][0] ^= 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ANCHOR:' + field + '$'):
                self.check(proof)
        for field in ('parent_height', 'non_account_count'):
            proof = copy.deepcopy(self.proof)
            proof[field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'ANCHOR:' + field + '$'):
                self.check(proof)

    def test_order_duplicates_rank_and_value_types_are_not_coerced(self):
        variants = []
        reordered = copy.deepcopy(self.proof)
        reordered['rows'][0:2] = reversed(reordered['rows'][0:2])
        variants.append(reordered)
        duplicate = copy.deepcopy(self.proof)
        duplicate['rows'].insert(1, copy.deepcopy(duplicate['rows'][0]))
        variants.append(duplicate)
        for field, value in (('rank', False), ('rank', oracle.MAX_ROWS), ('key', 1), ('value', False)):
            changed = copy.deepcopy(self.proof)
            changed['rows'][0][field] = value
            variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed['rows'][:2]), self.assertRaises(ValueError):
                self.check(changed)

    def test_frontier_zero_overlap_duplicate_reorder_and_digest_changes_fail(self):
        self.assertGreaterEqual(len(self.proof['frontier']), 2)
        variants = []
        for field, value in (('first', False), ('count', 0), ('count', oracle.MAX_ROWS+1), ('digest', [0]*32)):
            changed = copy.deepcopy(self.proof)
            changed['frontier'][0][field] = value
            variants.append(changed)
        duplicate = copy.deepcopy(self.proof)
        duplicate['frontier'].insert(1, duplicate['frontier'][0])
        variants.append(duplicate)
        reordered = copy.deepcopy(self.proof)
        reordered['frontier'].reverse()
        variants.append(reordered)
        for changed in variants:
            with self.subTest(changed=changed['frontier'][:2]), self.assertRaises(ValueError):
                self.check(changed)

    def test_exact_json_shape_dimensions_and_byte_bounds(self):
        for field, value in (('non_account_count', oracle.MAX_ROWS+1), ('parent_height', True),
                             ('parent_checkpoint', [True]*32), ('schema', 'different')):
            changed = copy.deepcopy(self.proof)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(changed)
        extra = copy.deepcopy(self.proof)
        extra['future_obligations_omitted'] = True
        with self.assertRaises(ValueError):
            self.check(extra)
        for partition in ({'x'*161: 0}, {'x': 'v'*4095}, {'account:'+'00'*32: 0}):
            with self.subTest(partition=list(partition)), self.assertRaises(ValueError):
                oracle.reference_partition(partition, self.anchor)
        valid = oracle.reference_partition({'x'*160: 'v'*4094}, self.anchor)
        self.assertEqual(len(valid['proof']['rows']), 1)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY$'):
            oracle.strict_json(b'{"rows":[],"rows":[]}')

    def test_serde_struct_bytes_are_canonical_independent_of_json_map_input_order(self):
        encoded = oracle.proof_bytes(self.proof)
        self.assertTrue(encoded.startswith(b'{"schema":"pon-monetary-obligation-range-v1","parent_checkpoint":'))
        self.assertEqual(len(encoded), self.reference['observation']['proof_json_bytes'])
        reordered = json.loads(json.dumps(self.proof, sort_keys=True))
        self.assertEqual(oracle.proof_bytes(reordered), encoded)
        self.check(reordered)


if __name__ == '__main__':
    unittest.main()
