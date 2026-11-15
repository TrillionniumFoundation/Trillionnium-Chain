"""Independent AAM1 arithmetic and canonical-boundary rejection controls.

These tests derive full trees locally.  Actual signed native observations are a
separate required CLI replay, not fabricated native evidence in this test suite.
"""
import copy
from itertools import combinations
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import account_archive_oracle as archive
import account_multiproof_oracle as oracle


def owner(number):
    return number.to_bytes(32, 'little')


class AccountMultiproofOracleTests(unittest.TestCase):
    def setUp(self):
        self.first, self.shared, self.third, self.outside, self.absent = map(owner, [1, 3800, 3, 4, 3801])
        self.checkpoint = bytes([17]) * 32
        self.accounts = {
            self.first: archive.Account(0, 91),
            self.shared: archive.Account(1234, 5),
            self.third: archive.Account(55, 2),
            self.outside: archive.Account(27, 0),
        }
        self.queries = [self.first, self.shared, self.third, self.absent]
        self.proof, self.root = oracle.from_full_accounts(self.accounts, self.checkpoint, self.queries)

    def verify(self, proof=None):
        return oracle.verify_proof(self.proof if proof is None else proof,
                                   self.checkpoint, self.root, len(self.accounts))

    def updates(self, replacements):
        return [dict(owner=list(key), before=self.accounts[key].as_json() if key in self.accounts else None,
                     after=value.as_json()) for key, value in sorted(replacements.items())]

    def test_full_level_construction_matches_separate_sparse_reference(self):
        expected, _ = archive.full_sparse(self.accounts)
        self.assertEqual(self.root, expected)
        self.assertEqual(oracle.fold(self.proof)['root'], expected)
        self.assertEqual(self.verify(), {key: self.accounts.get(key) for key in self.queries})
        reordered, root = oracle.from_full_accounts(dict(reversed(tuple(self.accounts.items()))),
                                                    self.checkpoint, reversed(self.queries))
        self.assertEqual((reordered, root), (self.proof, self.root))

    def test_empty_tree_nonmembership_can_create_multiple_accounts(self):
        proof, root = oracle.from_full_accounts({}, self.checkpoint, [self.first, self.shared])
        self.assertEqual(root, archive.EMPTY[0])
        self.assertEqual(proof['frontier'], [])
        self.assertEqual(oracle.verify_proof(proof, self.checkpoint, root, 0),
                         {self.first: None, self.shared: None})
        updates = [dict(owner=list(key), before=None, after=archive.Account(8, 0).as_json())
                   for key in sorted([self.first, self.shared])]
        changed, _ = oracle.root_for_updates(proof, self.checkpoint, root, updates, 0)
        self.assertEqual(changed, archive.full_sparse({self.first: archive.Account(8, 0),
                                                       self.shared: archive.Account(8, 0)})[0])

    def test_empty_query_makes_no_empty_tree_claim(self):
        proof, root = oracle.from_full_accounts(self.accounts, self.checkpoint, [])
        self.assertIsNone(oracle.fold(proof)['root'])
        self.assertEqual(oracle.verify_proof(proof, self.checkpoint, root, len(self.accounts)), {})
        self.assertNotEqual(root, archive.EMPTY[0])
        self.assertEqual(oracle.root_for_updates(proof, self.checkpoint, root, []),
                         (root, dict(changed_accounts=0, changed_forks=0, branch_hashes=0)))
        self.assertEqual(len(oracle.encode_proof(proof)), 44)
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_UPDATE_BUDGET$'):
            oracle.root_for_updates(proof, self.checkpoint, root,
                [dict(owner=list(self.first), before=None, after=archive.Account(1, 0).as_json())])

    def test_absent_owner_inside_shared_twelve_bit_prefix_gets_one_boundary(self):
        proof, root = oracle.from_full_accounts({self.first: self.accounts[self.first]},
                                                self.checkpoint, [self.shared])
        self.assertEqual(len(proof['frontier']), 1)
        self.assertEqual(proof['frontier'][0]['depth'], 13)
        self.assertEqual(proof['accounts'][0]['account'], None)
        self.assertEqual(oracle.verify_proof(proof, self.checkpoint, root, 1), {self.shared: None})
        self.assertEqual(oracle.proof_observation(proof)['verification_branch_hashes'], 256)
        self.assertEqual(len(oracle.encode_proof(proof)), 44 + 33 + 66)

    def test_queries_covering_every_account_have_no_frontier(self):
        proof, root = oracle.from_full_accounts(self.accounts, self.checkpoint, self.accounts)
        self.assertEqual(proof['frontier'], [])
        self.assertEqual(root, self.root)
        self.assertEqual(len(oracle.encode_proof(proof)), 44 + 49 * len(self.accounts))
        self.assertEqual(oracle.expected_archive_reads(self.accounts, list(self.accounts)),
                         2 * len(self.accounts) - 1)

    def test_frontier_covers_only_nonempty_maximal_outside_query_slots(self):
        rows = self.proof['frontier']
        self.assertGreater(len(rows), 0)
        for row in rows:
            depth = row['depth']
            prefix = int.from_bytes(bytes(row['prefix']), 'big')
            self.assertEqual(prefix % (1 << (256 - depth)), 0)
            self.assertNotEqual(bytes(row['digest']), archive.EMPTY[depth])
        self.assertEqual(oracle.fold(self.proof)['root'], self.root)
        self.assertLess(len(oracle.encode_proof(self.proof)),
                        archive.MIN_WITNESS_BYTES * len(self.queries))

    def test_binary_layout_uses_explicit_presence_little_endian_values_and_counts(self):
        value = archive.Account(0x0102030405060708, archive.U64_MAX)
        proof, _ = oracle.from_full_accounts({self.first: value}, self.checkpoint, [self.first])
        expected = (b'AAM1' + self.checkpoint + b'\1\0\0\0' + b'\0\0\0\0'
                    + self.first + b'\1' + b'\x08\x07\x06\x05\x04\x03\x02\x01' + b'\xff' * 8)
        self.assertEqual(oracle.encode_proof(proof), expected)
        self.assertEqual(oracle.decode_proof(expected), proof)
        self.assertEqual(len(expected), 93)

    def test_frontier_encoding_has_two_byte_depth_then_exact_prefix_and_digest(self):
        raw = oracle.encode_proof(self.proof)
        account_bytes = sum(49 if row['account'] is not None else 33 for row in self.proof['accounts'])
        offset = 44 + account_bytes
        row = self.proof['frontier'][0]
        self.assertEqual(raw[offset:offset + 66], row['depth'].to_bytes(2, 'little')
                         + bytes(row['prefix']) + bytes(row['digest']))
        self.assertEqual(oracle.decode_proof(raw), self.proof)

    def test_codec_rejects_magic_presence_truncation_and_trailing_bytes(self):
        raw = oracle.encode_proof(self.proof)
        changed_flag = raw[:76] + b'\2' + raw[77:]
        for invalid in [b'', raw[:43], b'AAM2' + raw[4:], changed_flag, raw[:-1], raw + b'\0']:
            with self.subTest(length=len(invalid)):
                with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ENCODING$'):
                    oracle.decode_proof(invalid)

    def test_declared_counts_and_raw_size_are_bounded_before_leaf_decode(self):
        for accounts, frontier in [(oracle.MAX_ACCOUNTS + 1, 0), (0, oracle.MAX_FRONTIER_NODES + 1),
                                   ((1 << 32) - 1, (1 << 32) - 1)]:
            raw = b'AAM1' + self.checkpoint + accounts.to_bytes(4, 'little') + frontier.to_bytes(4, 'little')
            with self.assertRaisesRegex(ValueError, '^MULTIPROOF_BUDGET$'):
                oracle.decode_proof(raw)
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ENCODING$'):
            oracle.decode_proof(b'AAM1' + self.checkpoint + b'\1\0\0\0' + b'\0' * 4)
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_BUDGET$'):
            oracle.decode_proof(bytes(oracle.MAX_ENCODED_BYTES + 1))
        self.assertEqual(oracle.MAX_ENCODED_BYTES, 7_561_821)

    def test_hash_path_order_is_distinct_from_owner_update_order(self):
        paths = [archive.key_path(bytes(row['owner'])) for row in self.proof['accounts']]
        owners = [bytes(row['owner']) for row in self.proof['accounts']]
        self.assertEqual(paths, sorted(paths))
        self.assertNotEqual(owners, sorted(owners))
        bad = copy.deepcopy(self.proof)
        bad['accounts'].sort(key=lambda row: bytes(row['owner']))
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ACCOUNT_ORDER$'):
            oracle.encode_proof(bad)

    def test_duplicate_query_and_duplicate_account_are_rejected(self):
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_DUPLICATE_QUERY$'):
            oracle.from_full_accounts(self.accounts, self.checkpoint, [self.first, self.first])
        bad = copy.deepcopy(self.proof)
        bad['accounts'].insert(0, copy.deepcopy(bad['accounts'][0]))
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ACCOUNT_ORDER$'):
            oracle.encode_proof(bad)

    def test_nonce_and_presence_remain_authenticated_at_zero_balance(self):
        for replacement in [None, dict(balance=0, nonce=0), dict(balance=0, nonce=90)]:
            bad = copy.deepcopy(self.proof)
            next(row for row in bad['accounts'] if bytes(row['owner']) == self.first)['account'] = replacement
            with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ROOT$'):
                self.verify(bad)
        bad = copy.deepcopy(self.proof)
        next(row for row in bad['accounts'] if bytes(row['owner']) == self.absent)['account'] = dict(balance=0, nonce=0)
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ROOT$'):
            self.verify(bad)

    def test_decoding_well_formed_wrong_digest_is_not_root_verification(self):
        bad = copy.deepcopy(self.proof)
        bad['frontier'][0]['digest'][0] ^= 1
        decoded = oracle.decode_proof(oracle.encode_proof(bad))
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ROOT$'):
            self.verify(decoded)

    def test_checkpoint_identity_and_frontier_count_are_not_inferred_from_leaves(self):
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_CHECKPOINT$'):
            oracle.verify_proof(self.proof, bytes([18]) * 32, self.root)
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_FRONTIER_COUNT$'):
            oracle.verify_proof(self.proof, self.checkpoint, self.root, 0)

    def test_omitted_nonempty_boundary_fails_root_verification(self):
        bad = copy.deepcopy(self.proof)
        bad['frontier'].pop()
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ROOT$'):
            self.verify(bad)

    def test_empty_noncanonical_and_nonmaximal_boundaries_are_rejected(self):
        empty = copy.deepcopy(self.proof)
        row = empty['frontier'][0]
        row['digest'] = list(archive.EMPTY[row['depth']])
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_EMPTY_FRONTIER$'):
            oracle.encode_proof(empty)
        suffix = copy.deepcopy(self.proof)
        self.assertLess(suffix['frontier'][0]['depth'], 256)
        suffix['frontier'][0]['prefix'][-1] |= 1
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_FRONTIER_PREFIX$'):
            oracle.encode_proof(suffix)
        deeper = copy.deepcopy(self.proof)
        deeper['frontier'][0]['depth'] += 1
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_BOUNDARY$'):
            oracle.encode_proof(deeper)

    def test_frontier_cannot_overlap_query_or_duplicate_another_frontier(self):
        overlapping = copy.deepcopy(self.proof)
        overlapping['frontier'] = [dict(depth=256, prefix=list(archive.key_path(self.first)), digest=[9] * 32)]
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_BOUNDARY$'):
            oracle.encode_proof(overlapping)
        duplicate = copy.deepcopy(self.proof)
        duplicate['frontier'].insert(0, copy.deepcopy(duplicate['frontier'][0]))
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_FRONTIER_ORDER$'):
            oracle.encode_proof(duplicate)
        proof, _ = oracle.from_full_accounts(self.accounts, self.checkpoint, [self.first])
        self.assertGreater(len(proof['frontier']), 1)
        proof['frontier'].reverse()
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_FRONTIER_ORDER$'):
            oracle.encode_proof(proof)

    def test_types_unknown_fields_and_unsigned_ranges_are_strict(self):
        for mutate in [lambda proof: proof.update(valid=True),
                       lambda proof: proof['accounts'][0].update(verified=True),
                       lambda proof: proof['frontier'][0].update(nonempty=True),
                       lambda proof: proof['checkpoint'].__setitem__(0, True),
                       lambda proof: proof['frontier'][0].__setitem__('depth', True),
                       lambda proof: proof['frontier'][0].__setitem__('depth', 0),
                       lambda proof: proof['frontier'][0].__setitem__('depth', 257)]:
            bad = copy.deepcopy(self.proof)
            mutate(bad)
            with self.assertRaises(ValueError):
                oracle.encode_proof(bad)
        for value in [True, -1, 1 << 64, 1.0]:
            bad = copy.deepcopy(self.proof)
            next(row for row in bad['accounts'] if row['account'] is not None)['account']['nonce'] = value
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_INTEGER$'):
                oracle.encode_proof(bad)

    def test_all_update_combinations_match_complete_new_trees(self):
        replacements = {self.first: archive.Account(19, 92), self.shared: archive.Account(0, 6),
                        self.third: archive.Account(73, 2), self.absent: archive.Account(50, 1)}
        before = archive.canonical(self.proof)
        for size in range(5):
            for selected in combinations(replacements, size):
                subset = {key: replacements[key] for key in selected}
                root, metrics = oracle.root_for_updates(self.proof, self.checkpoint, self.root,
                                                        self.updates(subset), len(self.accounts))
                self.assertEqual(root, archive.full_sparse({**self.accounts, **subset})[0])
                self.assertEqual(metrics['changed_accounts'], size)
                self.assertLessEqual(metrics['branch_hashes'], 256 * size)
                self.assertLessEqual(metrics['changed_forks'], max(0, len(self.queries) + len(self.proof['frontier']) - 1))
        self.assertEqual(archive.canonical(self.proof), before)

    def test_original_parent_updates_are_repeatable_and_do_not_accumulate_between_calls(self):
        first = self.updates({self.first: archive.Account(20, 92)})
        second = self.updates({self.shared: archive.Account(0, 7)})
        one, _ = oracle.root_for_updates(self.proof, self.checkpoint, self.root, first)
        two, _ = oracle.root_for_updates(self.proof, self.checkpoint, self.root, second)
        again, _ = oracle.root_for_updates(self.proof, self.checkpoint, self.root, first)
        self.assertEqual(one, again)
        self.assertEqual(two, archive.full_sparse({**self.accounts, self.shared: archive.Account(0, 7)})[0])
        self.assertNotEqual(two, archive.full_sparse({**self.accounts, self.first: archive.Account(20, 92),
                                                    self.shared: archive.Account(0, 7)})[0])

    def test_updates_reject_before_mismatch_nonce_rollback_deletion_and_noop(self):
        base = self.updates({self.first: archive.Account(9, 92)})
        cases = [(dict(balance=0, nonce=90), dict(balance=9, nonce=92), 'MULTIPROOF_UPDATE_BEFORE'),
                 (self.accounts[self.first].as_json(), dict(balance=9, nonce=90), 'MULTIPROOF_NONCE_ROLLBACK'),
                 (self.accounts[self.first].as_json(), self.accounts[self.first].as_json(), 'MULTIPROOF_UPDATE_NOOP'),
                 (self.accounts[self.first].as_json(), None, 'ARCHIVE_ACCOUNT_FIELDS')]
        for before, after, code in cases:
            bad = copy.deepcopy(base)
            bad[0].update(before=before, after=after)
            with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                oracle.root_for_updates(self.proof, self.checkpoint, self.root, bad)

    def test_updates_reject_missing_witness_duplicate_and_wrong_owner_order(self):
        missing = self.updates({self.outside: archive.Account(8, 0)})
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_MISSING_WITNESS$'):
            oracle.root_for_updates(self.proof, self.checkpoint, self.root, missing)
        updates = self.updates({self.first: archive.Account(8, 92), self.shared: archive.Account(0, 6)})
        for bad in [updates[::-1], [updates[0], updates[0]]]:
            with self.assertRaisesRegex(ValueError, '^MULTIPROOF_UPDATE_ORDER$'):
                oracle.root_for_updates(self.proof, self.checkpoint, self.root, bad)

    def test_full_state_deltas_preserve_zero_account_and_reject_deletion(self):
        parent = {'account:' + key.hex(): value.as_json() for key, value in self.accounts.items()}
        parent['meta:issued'] = 2000
        child = copy.deepcopy(parent)
        child['account:' + self.shared.hex()] = dict(balance=0, nonce=6)
        child['account:' + self.absent.hex()] = dict(balance=0, nonce=1)
        child['meta:issued'] += 10
        changes = oracle.original_parent_updates(parent, child)
        self.assertEqual(changes, self.updates({self.shared: archive.Account(0, 6), self.absent: archive.Account(0, 1)}))
        del child['account:' + self.first.hex()]
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_ACCOUNT_DELETION$'):
            oracle.original_parent_updates(parent, child)

    def test_archive_read_counter_includes_divergent_child_but_no_empty_root_read(self):
        self.assertEqual(oracle.expected_archive_reads({}, [self.first]), 0)
        self.assertEqual(oracle.expected_archive_reads(self.accounts, []), 0)
        self.assertEqual(oracle.expected_archive_reads({self.first: self.accounts[self.first]}, [self.shared]), 1)
        for count in range(1, len(self.queries) + 1):
            reads = oracle.expected_archive_reads(self.accounts, self.queries[:count])
            self.assertGreaterEqual(reads, 1)
            self.assertLessEqual(reads, 2 * len(self.accounts) - 1)

    def query_fixture(self):
        state = {'account:' + key.hex(): value.as_json() for key, value in self.accounts.items()}
        state['meta:issued'] = sum(value.balance for value in self.accounts.values())
        context = {name: [number] * 32 for number, name in enumerate(['network', 'parameters', 'genesis'], 1)}
        branch, height = bytes([73]) * 32, 34
        checkpoint, _ = archive.derive_checkpoint(context, branch, None, height,
            archive.source_state_root(state), self.accounts)
        proof, _ = oracle.from_full_accounts(self.accounts, bytes(checkpoint['id']), self.queries)
        raw = oracle.encode_proof(proof)
        query = dict(checkpoint=checkpoint, proof=proof, proof_hex=raw.hex(), encoded_bytes=len(raw),
            requested_owners=[key.hex() for key in self.queries],
            observation=dict(archive_point_reads=oracle.expected_archive_reads(self.accounts, self.queries),
                             expanded_witnesses_allocated=0, proof=oracle.proof_observation(proof)))
        return query, context, branch, height, state

    def test_native_query_companion_binds_full_state_context_and_requested_owners(self):
        query, context, branch, height, state = self.query_fixture()
        result = oracle.checked_native_query(query, context, branch, height, state, self.queries)
        self.assertEqual(result['account_root'], self.root.hex())
        self.assertEqual((result['present_accounts'], result['absent_accounts']), (3, 1))
        self.assertEqual(result['requested_owners'], [key.hex() for key in self.queries])
        changed = copy.deepcopy(state)
        changed['meta:issued'] += 1
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_NATIVE_QUERY_CHECKPOINT$'):
            oracle.checked_native_query(query, context, branch, height, changed, self.queries)
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_NATIVE_QUERY_REQUESTED$'):
            oracle.checked_native_query(query, context, branch, height, state, self.queries[:-1])
        with self.assertRaisesRegex(ValueError, '^MULTIPROOF_NATIVE_QUERY_CHECKPOINT$'):
            oracle.checked_native_query(query, context, branch, height + 1, state, self.queries)

    def test_native_query_companion_rejects_missing_wire_bytes_and_forged_work_counts(self):
        query, context, branch, height, state = self.query_fixture()
        for mutate, code in [
            (lambda value: value.pop('proof_hex'), 'MULTIPROOF_NATIVE_QUERY_FIELDS'),
            (lambda value: value.__setitem__('proof_hex', value['proof_hex'] + '00'), 'MULTIPROOF_NATIVE_QUERY_BYTES'),
            (lambda value: value.__setitem__('encoded_bytes', True), 'MULTIPROOF_NATIVE_QUERY_LENGTH'),
            (lambda value: value['observation'].__setitem__('archive_point_reads', 0), 'MULTIPROOF_NATIVE_QUERY_CONSTRUCTION'),
            (lambda value: value['observation']['proof'].__setitem__('verification_branch_hashes', 0), 'MULTIPROOF_NATIVE_QUERY_CONSTRUCTION'),
            (lambda value: value['proof']['accounts'].pop(), 'MULTIPROOF_NATIVE_QUERY_PROOF'),
        ]:
            bad = copy.deepcopy(query)
            mutate(bad)
            with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                oracle.checked_native_query(bad, context, branch, height, state, self.queries)

    def test_cli_writes_failure_receipt_without_overwriting_input_or_old_receipt(self):
        script = Path(oracle.__file__)
        with tempfile.TemporaryDirectory() as directory:
            native, output = Path(directory) / 'native.json', Path(directory) / 'oracle.json'
            native.write_text('{"schema":"wrong"}\n', encoding='utf-8')
            original = native.read_bytes()
            process = subprocess.run([sys.executable, str(script), str(native), '--output', str(output)],
                                     capture_output=True, check=False)
            self.assertNotEqual(process.returncode, 0)
            report = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(report['result'], 'FAIL')
            self.assertEqual(native.read_bytes(), original)
            saved = output.read_bytes()
            second = subprocess.run([sys.executable, str(script), '--native-json', str(native),
                                     '--output', str(output)], capture_output=True, check=False)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), saved)
            same = subprocess.run([sys.executable, str(script), str(native), '--output', str(native)],
                                  capture_output=True, check=False)
            self.assertNotEqual(same.returncode, 0)
            self.assertEqual(native.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
