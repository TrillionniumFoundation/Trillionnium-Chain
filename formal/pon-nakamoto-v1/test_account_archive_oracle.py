"""Pure archive arithmetic tests; native recovery needs the separate bridge."""
import copy
from hashlib import sha256
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import sqlite3

import account_archive_oracle as oracle


class AccountArchiveOracleTests(unittest.TestCase):
    def setUp(self):
        self.first = bytes(range(32))
        self.second = bytes(range(32, 64))
        self.missing = bytes([201]) * 32
        self.checkpoint = bytes([17]) * 32
        self.values = {
            self.first: oracle.Account(0, 91),
            self.second: oracle.Account(1234, 5),
        }
        self.root, self.paths = oracle.full_sparse(
            self.values, [self.first, self.second, self.missing])

    def witness(self, owner):
        return oracle.witness_json(self.checkpoint, owner, self.values.get(owner), self.paths[owner])

    def test_domain_framing_is_explicit_and_length_delimited(self):
        manual = b'TRNM-PON1\0\x01\x00x\x02\x00\x00\x00ab\x01\x00\x00\x00c'
        self.assertEqual(oracle.digest(b'x', b'ab', b'c'), sha256(manual).digest())
        self.assertNotEqual(oracle.digest(b'x', b'ab', b'c'), oracle.digest(b'x', b'a', b'bc'))
        self.assertNotEqual(oracle.digest(b'x', b''), oracle.digest(b'x'))

    def test_empty_tree_has_real_nonmembership_proof(self):
        root, paths = oracle.full_sparse({}, [self.missing])
        self.assertEqual(root, oracle.EMPTY[0])
        self.assertEqual(paths[self.missing], oracle.EMPTY[1:])
        witness = oracle.witness_json(self.checkpoint, self.missing, None, paths[self.missing])
        self.assertIsNone(oracle.verify_witness(witness, self.checkpoint, root, self.missing))

    def test_full_integer_tree_agrees_with_member_and_nonmember_folds(self):
        for owner in [self.first, self.second, self.missing]:
            self.assertEqual(oracle.verify_witness(self.witness(owner), self.checkpoint,
                                                   self.root, owner), self.values.get(owner))
        reverse_root, _ = oracle.full_sparse(dict(reversed(tuple(self.values.items()))))
        self.assertEqual(self.root, reverse_root)

    def test_zero_balance_nonzero_nonce_remains_a_committed_member(self):
        self.assertEqual(oracle.require_member(self.witness(self.first), self.checkpoint,
                                               self.root, self.first), oracle.Account(0, 91))
        reset = dict(self.values)
        reset[self.first] = oracle.Account(0, 0)
        self.assertNotEqual(oracle.full_sparse(reset)[0], self.root)
        deleted = dict(self.values)
        del deleted[self.first]
        self.assertNotEqual(oracle.full_sparse(deleted)[0], self.root)

    def test_real_owners_diverge_inside_a_twelve_bit_compressed_prefix(self):
        first, absent = (number.to_bytes(32, 'little') for number in [1, 3800])
        first_path = int.from_bytes(oracle.key_path(first), 'big')
        absent_path = int.from_bytes(oracle.key_path(absent), 'big')
        self.assertEqual(256 - (first_path ^ absent_path).bit_length(), 12)
        values = {first: oracle.Account(0, 17)}
        root, paths = oracle.full_sparse(values, [first, absent])
        populated = [depth for depth, sibling in enumerate(paths[absent])
                     if sibling != oracle.EMPTY[depth + 1]]
        self.assertEqual(populated, [12])
        proof = oracle.witness_json(self.checkpoint, absent, None, paths[absent])
        self.assertIsNone(oracle.verify_witness(proof, self.checkpoint, root, absent))
        values[absent] = oracle.Account(5, 2)
        new_root, _ = oracle.full_sparse(values)
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            oracle.verify_witness(proof, self.checkpoint, new_root, absent)

    def test_wrong_owner_cannot_reuse_a_proof(self):
        witness = self.witness(self.first)
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_OWNER$'):
            oracle.verify_witness(witness, self.checkpoint, self.root, self.second)
        witness['owner'] = list(self.second)
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            oracle.verify_witness(witness, self.checkpoint, self.root, self.second)

    def test_old_checkpoint_rejected_even_when_state_root_matches(self):
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_CHECKPOINT$'):
            oracle.verify_witness(self.witness(self.first), bytes([18]) * 32,
                                  self.root, self.first)

    def test_claiming_member_absent_or_absent_member_is_rejected(self):
        erased = self.witness(self.first)
        erased['account'] = None
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            oracle.verify_witness(erased, self.checkpoint, self.root, self.first)
        invented = self.witness(self.missing)
        invented['account'] = {'balance': 0, 'nonce': 0}
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            oracle.verify_witness(invented, self.checkpoint, self.root, self.missing)

    def test_corrupt_and_truncated_siblings_fail(self):
        corrupted = self.witness(self.first)
        corrupted['siblings'][0][0] ^= 1
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            oracle.verify_witness(corrupted, self.checkpoint, self.root, self.first)
        for length in [0, 255, 257]:
            truncated = self.witness(self.first)
            truncated['siblings'] = (truncated['siblings'] + [[0] * 32])[:length]
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_WITNESS_LENGTH$'):
                oracle.verify_witness(truncated, self.checkpoint, self.root, self.first)

    def test_missing_proof_is_unavailable_not_zero_nonce(self):
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_DATA_UNAVAILABLE$'):
            oracle.verify_witness(None, self.checkpoint, self.root, self.missing)
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ACCOUNT_ABSENT$'):
            oracle.require_member(self.witness(self.missing), self.checkpoint,
                                  self.root, self.missing)

    def test_binary_codec_has_exact_member_and_nonmember_lengths(self):
        for owner, length in [(self.first, 8277), (self.missing, 8261)]:
            witness = self.witness(owner)
            raw = oracle.encode_witness(witness)
            self.assertEqual(len(raw), length)
            self.assertEqual(raw[:4], b'AAW1')
            self.assertEqual(raw[4:36], self.checkpoint)
            self.assertEqual(raw[36:68], owner)
            self.assertEqual(oracle.decode_witness(raw), witness)
        raw = oracle.encode_witness(self.witness(self.first))
        self.assertEqual(raw[68], 1)
        self.assertEqual(raw[69:85], bytes(8) + (91).to_bytes(8, 'little'))

    def test_binary_codec_rejects_magic_flag_truncation_and_trailing_bytes(self):
        raw = oracle.encode_witness(self.witness(self.first))
        invalid_flag = raw[:68] + b'\2' + raw[69:]
        false_absent = raw[:68] + b'\0' + raw[69:]
        for invalid in [b'', raw[:3], b'AAW2' + raw[4:], invalid_flag,
                        false_absent, raw[:-1], raw + b'\0']:
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_WITNESS_ENCODING$'):
                oracle.decode_witness(invalid)

    def test_decoding_well_formed_bytes_is_not_proof_verification(self):
        raw = bytearray(oracle.encode_witness(self.witness(self.first)))
        raw[-1] ^= 1
        decoded = oracle.decode_witness(bytes(raw))
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ROOT$'):
            oracle.verify_witness(decoded, self.checkpoint, self.root, self.first)

    def test_account_fields_and_unsigned_ranges_are_strict(self):
        self.assertEqual(oracle.account({'balance': oracle.U64_MAX, 'nonce': oracle.U64_MAX}),
                         oracle.Account(oracle.U64_MAX, oracle.U64_MAX))
        for value in [True, 1.0, -1, 1 << 64]:
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_INTEGER$'):
                oracle.Account(value, 0)
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_INTEGER$'):
                oracle.Account(0, value)
        for value in [{'balance': 0}, {'nonce': 0}, {'balance': 0, 'nonce': 0, 'deleted': False}]:
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_ACCOUNT_FIELDS$'):
                oracle.account(value)

    def test_state_import_requires_canonical_account_keys_and_full_nonce(self):
        state = {'account:' + self.first.hex(): {'balance': 0, 'nonce': 91}, 'meta:issued': 0}
        self.assertEqual(oracle.accounts_from_state(state), {self.first: oracle.Account(0, 91)})
        for suffix in ['ab', self.first.hex().upper(), self.first.hex() + '00']:
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_STATE_KEY$'):
                oracle.accounts_from_state({'account:' + suffix: {'balance': 0, 'nonce': 0}})
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_ACCOUNT_FIELDS$'):
            oracle.accounts_from_state({'account:' + self.first.hex(): {'balance': 0}})

    def test_native_hash_arrays_do_not_accept_booleans_or_noncanonical_fields(self):
        witness = self.witness(self.first)
        for field in ['checkpoint', 'owner']:
            changed = copy.deepcopy(witness)
            changed[field][0] = True
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_HASH_BYTES$'):
                oracle.verify_witness(changed, self.checkpoint, self.root, self.first)
        extra = copy.deepcopy(witness)
        extra['valid'] = True
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_WITNESS_FIELDS$'):
            oracle.verify_witness(extra, self.checkpoint, self.root, self.first)

    def test_evidence_decoder_rejects_duplicate_keys_and_nonfinite_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'observation.json'
            for raw, code in [(b'{"root":1,"root":2}', 'ARCHIVE_DUPLICATE_JSON_KEY'),
                              (b'{"value":NaN}', 'ARCHIVE_JSON_NUMBER')]:
                path.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    oracle.load_json(path)

    def test_source_root_binds_nonaccount_state_while_archive_root_does_not(self):
        state = {'account:' + self.first.hex(): {'balance': 0, 'nonce': 91}, 'meta:issued': 0}
        changed = dict(state)
        changed['meta:issued'] = 1
        self.assertNotEqual(oracle.source_state_root(state), oracle.source_state_root(changed))
        self.assertEqual(oracle.full_sparse(oracle.accounts_from_state(state))[0],
                         oracle.full_sparse(oracle.accounts_from_state(changed))[0])

    def test_node_record_commitment_is_separate_from_sparse_root(self):
        details = oracle.full_sparse_details(self.values)
        self.assertEqual(len(details['records']), 2 * len(self.values) - 1)
        self.assertEqual(sorted(map(len, details['records'].values())), [49, 49, 163])
        self.assertNotEqual(details['root'], details['root_node'])
        for identity, raw in details['records'].items():
            oracle.decode_node(identity, raw)
            tampered = raw[:-1] + bytes([raw[-1] ^ 1])
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_NODE_ID$'):
                oracle.decode_node(identity, tampered)

    def fixture_checkpoint(self):
        context = {name: [number] * 32 for number, name in enumerate(
            ['network', 'parameters', 'genesis'], 1)}
        return oracle.derive_checkpoint(context, bytes([3]) * 32, None, 0, None, self.values)

    def test_checkpoint_identity_binds_context_branch_parent_and_all_roots(self):
        checkpoint, _ = self.fixture_checkpoint()
        raw = oracle.checkpoint_record(checkpoint)
        self.assertEqual(len(raw), 311)
        self.assertEqual(oracle.decode_checkpoint(raw), checkpoint)
        for field in ['branch', 'account_root', 'root_node']:
            changed = copy.deepcopy(checkpoint)
            changed[field][0] ^= 1
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_CHECKPOINT_ID$'):
                oracle.checkpoint_record(changed)
        for field in ['parent', 'source_state_root']:
            changed = copy.deepcopy(checkpoint)
            changed[field] = [0] * 32
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_CHECKPOINT_ID$'):
                oracle.checkpoint_record(changed)
        changed = copy.deepcopy(checkpoint)
        changed['context']['network'][0] ^= 1
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_CHECKPOINT_ID$'):
            oracle.checkpoint_record(changed)

    def test_optional_zero_is_not_optional_absence_and_none_bytes_are_canonical(self):
        self.assertNotEqual(oracle.optional_hash(None), oracle.optional_hash([0] * 32))
        checkpoint, _ = self.fixture_checkpoint()
        raw = bytearray(oracle.checkpoint_record(checkpoint))
        # parent flag follows AAC1, id, three context hashes and branch.
        parent_flag = 4 + 32 + 4 * 32
        raw[parent_flag + 1] = 1
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_CHECKPOINT_OPTION$'):
            oracle.decode_checkpoint(bytes(raw))

    def write_sqlite_fixture(self, path):
        checkpoint, details = self.fixture_checkpoint()
        identity = oracle.hash_bytes(checkpoint['id'])
        active = {'checkpoint': checkpoint['id'], 'generation': 1}
        with sqlite3.connect(path) as db:
            db.executescript('''
                CREATE TABLE archive_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL);
                CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);
                CREATE TABLE archive_checkpoints(id BLOB PRIMARY KEY,branch BLOB UNIQUE NOT NULL,data BLOB NOT NULL);
                CREATE TABLE archive_active(singleton INTEGER PRIMARY KEY,checkpoint BLOB NOT NULL,generation INTEGER NOT NULL);
            ''')
            db.executemany('INSERT INTO archive_meta VALUES(?,?)', [
                ('schema', oracle.SCHEMA.encode('ascii')),
                ('context', oracle.context_bytes(checkpoint['context']))])
            db.executemany('INSERT INTO archive_nodes VALUES(?,?)', details['records'].items())
            db.execute('INSERT INTO archive_checkpoints VALUES(?,?,?)',
                       (identity, oracle.hash_bytes(checkpoint['branch']), oracle.checkpoint_record(checkpoint)))
            db.execute('INSERT INTO archive_active VALUES(1,?,1)', (identity,))
        db.close()
        return checkpoint, details, active

    def test_oracle_sqlite_fixture_is_read_only_and_detects_missing_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.sqlite'
            checkpoint, details, active = self.write_sqlite_fixture(path)
            expected = {oracle.hash_bytes(checkpoint['id']): oracle.checkpoint_record(checkpoint)}
            before = path.read_bytes()
            result = oracle.inspect_sqlite(path, checkpoint['context'], expected, details['records'], active)
            self.assertEqual(result['counts'], {
                'node_rows': 3, 'node_payload_bytes': 49 + 49 + 163, 'checkpoint_rows': 1})
            self.assertEqual(path.read_bytes(), before)
            with sqlite3.connect(path) as db:
                identity = next(identity for identity, raw in details['records'].items() if raw[0] == 0)
                db.execute('DELETE FROM archive_nodes WHERE id=?', (identity,))
            db.close()
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_DATA_UNAVAILABLE$'):
                oracle.inspect_sqlite(path, checkpoint['context'], expected, details['records'], active)

    def test_oracle_sqlite_fixture_refuses_nonempty_wal_without_reading_it_as_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.sqlite'
            checkpoint, details, active = self.write_sqlite_fixture(path)
            Path(str(path) + '-wal').write_bytes(b'not-a-checkpointed-database')
            with self.assertRaisesRegex(ValueError, '^ARCHIVE_DATABASE_WAL$'):
                oracle.inspect_sqlite(path, checkpoint['context'], {}, details['records'], active)

    def test_json_identity_does_not_coerce_boolean_metadata_to_integer(self):
        with self.assertRaisesRegex(ValueError, '^METADATA_TYPE$'):
            oracle.equal_json({'generation': True}, {'generation': 1}, 'METADATA_TYPE')

    def test_empty_native_campaign_cannot_be_a_successful_comparison(self):
        observed = dict(schema='pon-account-archive-native-observation-v1', reopened=True,
                        archive_used_for_native_execution=False, protocol_capacity_changed=False,
                        public_data_availability_accepted=False,
                        context={name: [1] * 32 for name in ['network', 'parameters', 'genesis']},
                        snapshots=[], operations=[])
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_SNAPSHOT_SET$'):
            oracle.check_small_observation(observed, 'must-not-be-opened.sqlite')

    def test_success_receipt_cannot_hide_a_failure_field(self):
        observed = {'schema': 'pon-account-archive-large-observation-v1', 'result': 'PASS', 'error': None}
        with self.assertRaisesRegex(ValueError, '^ARCHIVE_OBSERVATION_FAILURE$'):
            oracle.check_large_observation(observed, 'must-not-be-opened.sqlite')

    def test_cli_failure_emits_fail_json_nonzero_exit_and_keeps_input_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory) / 'observation.json'
            database = Path(directory) / 'untouched.sqlite'
            native.write_text('{"schema":"unknown"}\n')
            database.write_bytes(b'untouched database sentinel')
            before_native, before_database = native.read_bytes(), database.read_bytes()
            result = subprocess.run([sys.executable, str(Path(oracle.__file__)),
                '--native-json', str(native), '--database', str(database)], capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            failure = json.loads(result.stdout)
            self.assertEqual(failure['result'], 'FAIL')
            self.assertEqual(failure['error'], 'ARCHIVE_OBSERVATION_SCHEMA')
            self.assertEqual(failure['error_type'], 'ValueError')
            self.assertIn(b'ARCHIVE_OBSERVATION_SCHEMA', result.stderr)
            self.assertNotIn(b'NameError', result.stderr)
            self.assertEqual(native.read_bytes(), before_native)
            self.assertEqual(database.read_bytes(), before_database)


if __name__ == '__main__':
    unittest.main(verbosity=2)
